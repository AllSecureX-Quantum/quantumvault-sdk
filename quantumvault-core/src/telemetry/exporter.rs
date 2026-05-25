//! Telemetry exporter for AllSecureX platform.

use super::{CryptoEvent, Metrics, TelemetryConfig};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Telemetry exporter that sends data to AllSecureX.
pub struct TelemetryExporter {
    config: TelemetryConfig,
    event_queue: Arc<RwLock<VecDeque<CryptoEvent>>>,
    #[allow(dead_code)]
    client: Option<reqwest::Client>,
}

impl TelemetryExporter {
    /// Create a new telemetry exporter.
    pub fn new(config: TelemetryConfig) -> Self {
        let client = if config.enabled {
            Some(
                reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(30))
                    .build()
                    .unwrap_or_default(),
            )
        } else {
            None
        };

        Self {
            config,
            event_queue: Arc::new(RwLock::new(VecDeque::new())),
            client,
        }
    }

    /// Queue an event for export.
    pub async fn queue_event(&self, event: CryptoEvent) {
        if !self.config.enabled {
            return;
        }

        let mut queue = self.event_queue.write().await;
        queue.push_back(event);

        // Flush if batch size reached
        if queue.len() >= self.config.batch_size {
            drop(queue);
            let _ = self.flush().await;
        }
    }

    /// Export metrics to AllSecureX.
    pub async fn export_metrics(&self, metrics: &Metrics) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let client = self
            .client
            .as_ref()
            .ok_or_else(|| Error::Telemetry("Telemetry client not initialized".into()))?;

        let api_key = self
            .config
            .api_key
            .as_ref()
            .ok_or_else(|| Error::Telemetry("API key not configured".into()))?;

        let payload = MetricsPayload {
            metrics: metrics.clone(),
            timestamp: chrono::Utc::now(),
            sdk_version: env!("CARGO_PKG_VERSION").to_string(),
        };

        let response = client
            .post(format!("{}/metrics", self.config.endpoint))
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| Error::Telemetry(format!("Failed to send metrics: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::Telemetry(format!(
                "Metrics export failed with status: {}",
                response.status()
            )));
        }

        Ok(())
    }

    /// Flush queued events to AllSecureX.
    pub async fn flush(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let events: Vec<CryptoEvent> = {
            let mut queue = self.event_queue.write().await;
            queue.drain(..).collect()
        };

        if events.is_empty() {
            return Ok(());
        }

        let client = self
            .client
            .as_ref()
            .ok_or_else(|| Error::Telemetry("Telemetry client not initialized".into()))?;

        let api_key = self
            .config
            .api_key
            .as_ref()
            .ok_or_else(|| Error::Telemetry("API key not configured".into()))?;

        let payload = EventsPayload {
            events,
            timestamp: chrono::Utc::now(),
            sdk_version: env!("CARGO_PKG_VERSION").to_string(),
        };

        let response = client
            .post(format!("{}/events", self.config.endpoint))
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| Error::Telemetry(format!("Failed to send events: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::Telemetry(format!(
                "Events export failed with status: {}",
                response.status()
            )));
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct MetricsPayload {
    metrics: Metrics,
    timestamp: chrono::DateTime<chrono::Utc>,
    sdk_version: String,
}

#[derive(Serialize, Deserialize)]
struct EventsPayload {
    events: Vec<CryptoEvent>,
    timestamp: chrono::DateTime<chrono::Utc>,
    sdk_version: String,
}
