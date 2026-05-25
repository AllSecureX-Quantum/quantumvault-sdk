//! Key lifecycle management.

use crate::{KeyEntry, KeyStatus};
use chrono::{DateTime, Duration, Utc};

/// Check if a key needs rotation based on its policy.
pub fn needs_rotation(entry: &KeyEntry) -> bool {
    if let Some(ref policy) = entry.rotation_policy {
        if !policy.auto_rotate {
            return false;
        }

        if let Some(next_rotation) = policy.next_rotation_at {
            return Utc::now() >= next_rotation;
        }

        // If no next_rotation_at, check based on last rotation or creation
        let last_rotation = policy.last_rotated_at.unwrap_or(entry.created_at);
        let rotation_due = last_rotation + Duration::days(policy.rotation_interval_days as i64);
        return Utc::now() >= rotation_due;
    }
    false
}

/// Check if a key is expiring soon (within the warning threshold).
pub fn is_expiring_soon(entry: &KeyEntry, warning_days: u32) -> bool {
    if let Some(expires_at) = entry.expires_at {
        let warning_threshold = Utc::now() + Duration::days(warning_days as i64);
        return expires_at <= warning_threshold && expires_at > Utc::now();
    }
    false
}

/// Check if a key has expired.
pub fn is_expired(entry: &KeyEntry) -> bool {
    if let Some(expires_at) = entry.expires_at {
        return Utc::now() > expires_at;
    }
    false
}

/// Calculate the next rotation date for a key.
pub fn calculate_next_rotation(entry: &KeyEntry) -> Option<DateTime<Utc>> {
    entry.rotation_policy.as_ref().map(|policy| {
        let base = policy.last_rotated_at.unwrap_or(entry.created_at);
        base + Duration::days(policy.rotation_interval_days as i64)
    })
}

/// Key lifecycle state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LifecycleState {
    /// Key is healthy and active.
    Healthy,
    /// Key is expiring soon.
    ExpiringSoon { days_remaining: u32 },
    /// Key is due for rotation.
    RotationDue,
    /// Key has expired.
    Expired,
    /// Key has been revoked.
    Revoked,
    /// Key is disabled.
    Disabled,
}

/// Get the lifecycle state of a key.
pub fn get_lifecycle_state(entry: &KeyEntry, warning_days: u32) -> LifecycleState {
    match entry.status {
        KeyStatus::Revoked => LifecycleState::Revoked,
        KeyStatus::Disabled => LifecycleState::Disabled,
        KeyStatus::Expired => LifecycleState::Expired,
        KeyStatus::Active | KeyStatus::Rotating | KeyStatus::PendingDeletion => {
            if is_expired(entry) {
                LifecycleState::Expired
            } else if is_expiring_soon(entry, warning_days) {
                let days = entry
                    .expires_at
                    .map(|exp| (exp - Utc::now()).num_days().max(0) as u32)
                    .unwrap_or(0);
                LifecycleState::ExpiringSoon {
                    days_remaining: days,
                }
            } else if needs_rotation(entry) {
                LifecycleState::RotationDue
            } else {
                LifecycleState::Healthy
            }
        }
    }
}

/// Lifecycle events for audit logging.
#[derive(Clone, Debug)]
pub enum LifecycleEvent {
    /// Key was created.
    Created { key_id: String, algorithm: String },
    /// Key was rotated.
    Rotated {
        old_key_id: String,
        new_key_id: String,
    },
    /// Key was revoked.
    Revoked { key_id: String, reason: String },
    /// Key expired.
    Expired { key_id: String },
    /// Key was deleted.
    Deleted { key_id: String },
    /// Key was accessed.
    Accessed { key_id: String, operation: String },
}
