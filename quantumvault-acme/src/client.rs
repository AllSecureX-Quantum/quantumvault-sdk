//! Client side of the ACME-PQC protocol.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use quantumvault_core::SigningKey;
use uuid::Uuid;

use crate::error::{AcmeError, Result};
use crate::proto::{
    Account, IssueOrderRequest, OrderResource, RegisterAccountRequest, PROTOCOL_VERSION,
};
use crate::signing::sign_request;

/// Tiny client that talks to a `qvacme-server`.
pub struct Client {
    base: String,
    http: reqwest::Client,
}

impl Client {
    /// Construct against a `qvacme-server` base URL, e.g.
    /// `http://127.0.0.1:8443`.
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        Ok(Self {
            base: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }

    /// Register a new account, returning the server-issued record.
    pub async fn register_account(
        &self,
        signing_key: &SigningKey,
        verifying_key_bytes: &[u8],
        key_id: &str,
        contact: Option<String>,
    ) -> Result<Account> {
        let body = RegisterAccountRequest {
            version: PROTOCOL_VERSION,
            algorithm: "ML-DSA-65".into(),
            verifying_key: B64.encode(verifying_key_bytes),
            key_id: key_id.to_string(),
            contact,
        };
        let signed = sign_request(&body, signing_key, key_id)?;
        let resp = self
            .http
            .post(format!("{}/v1/accounts", self.base))
            .json(&signed)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(AcmeError::Http(format!(
                "register_account failed: HTTP {}",
                resp.status()
            )));
        }
        let acc: Account = resp.json().await?;
        Ok(acc)
    }

    /// Submit an order. Returns the server's order resource.
    pub async fn submit_order(
        &self,
        signing_key: &SigningKey,
        account_id: &str,
        subject_cn: &str,
        sans: Vec<String>,
        subject_verifying_key_bytes: &[u8],
        subject_key_id: &str,
        validity_days: i64,
    ) -> Result<OrderResource> {
        let body = IssueOrderRequest {
            version: PROTOCOL_VERSION,
            account_id: account_id.to_string(),
            subject_cn: subject_cn.to_string(),
            sans,
            subject_verifying_key: B64.encode(subject_verifying_key_bytes),
            subject_key_id: subject_key_id.to_string(),
            validity_days,
            nonce: Uuid::new_v4().to_string(),
        };
        let signed = sign_request(&body, signing_key, &signing_key.key_id)?;
        let resp = self
            .http
            .post(format!("{}/v1/orders", self.base))
            .json(&signed)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(AcmeError::Http(format!(
                "submit_order failed: HTTP {}",
                resp.status()
            )));
        }
        Ok(resp.json().await?)
    }

    /// Poll one order by id.
    pub async fn get_order(&self, id: &str) -> Result<OrderResource> {
        let resp = self
            .http
            .get(format!("{}/v1/orders/{}", self.base, id))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(AcmeError::Http(format!(
                "get_order failed: HTTP {}",
                resp.status()
            )));
        }
        Ok(resp.json().await?)
    }

    /// Download the issued certificate JSON.
    pub async fn get_certificate(&self, order_id: &str) -> Result<serde_json::Value> {
        let resp = self
            .http
            .get(format!("{}/v1/orders/{}/certificate", self.base, order_id))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(AcmeError::Http(format!(
                "get_certificate failed: HTTP {}",
                resp.status()
            )));
        }
        Ok(resp.json().await?)
    }

    /// Server health probe.
    pub async fn health(&self) -> Result<serde_json::Value> {
        let resp = self
            .http
            .get(format!("{}/v1/health", self.base))
            .send()
            .await?;
        Ok(resp.json().await?)
    }
}
