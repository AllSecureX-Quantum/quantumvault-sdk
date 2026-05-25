//! Key usage policies and access control.

use crate::error::{KeyError, KeyResult};
use crate::KeyEntry;
use quantumvault_core::Algorithm;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Key usage policy defining what operations are allowed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsagePolicy {
    /// Allowed operations.
    pub allowed_operations: HashSet<Operation>,
    /// Maximum uses per day (0 = unlimited).
    pub max_daily_uses: u32,
    /// Maximum uses total (0 = unlimited).
    pub max_total_uses: u64,
    /// Allowed IP addresses (empty = all allowed).
    pub allowed_ips: Vec<String>,
    /// Allowed principals (user/service IDs).
    pub allowed_principals: Vec<String>,
    /// Require MFA for operations.
    pub require_mfa: bool,
    /// Time-based restrictions.
    pub time_restrictions: Option<TimeRestriction>,
}

impl Default for UsagePolicy {
    fn default() -> Self {
        Self {
            allowed_operations: [
                Operation::Encrypt,
                Operation::Decrypt,
                Operation::Sign,
                Operation::Verify,
            ]
            .into_iter()
            .collect(),
            max_daily_uses: 0,
            max_total_uses: 0,
            allowed_ips: Vec::new(),
            allowed_principals: Vec::new(),
            require_mfa: false,
            time_restrictions: None,
        }
    }
}

/// Cryptographic operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Operation {
    /// Encryption operation.
    Encrypt,
    /// Decryption operation.
    Decrypt,
    /// Signing operation.
    Sign,
    /// Verification operation.
    Verify,
    /// Key derivation.
    Derive,
    /// Key wrapping.
    Wrap,
    /// Key unwrapping.
    Unwrap,
    /// Export public key.
    ExportPublic,
    /// Export private key (highly restricted).
    ExportPrivate,
}

/// Time-based restrictions for key usage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeRestriction {
    /// Allowed start hour (0-23).
    pub start_hour: u8,
    /// Allowed end hour (0-23).
    pub end_hour: u8,
    /// Allowed days of week (0=Sunday, 6=Saturday).
    pub allowed_days: Vec<u8>,
    /// Timezone (e.g., "UTC", "America/New_York").
    pub timezone: String,
}

/// Access control policy for a key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessPolicy {
    /// Owner of the key.
    pub owner: String,
    /// Access control entries.
    pub acl: Vec<AccessControlEntry>,
    /// Default deny all not explicitly allowed.
    pub default_deny: bool,
}

/// Access control entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessControlEntry {
    /// Principal (user/role ID).
    pub principal: String,
    /// Allowed operations.
    pub operations: HashSet<Operation>,
    /// Effect (allow/deny).
    pub effect: Effect,
    /// Conditions for this ACE.
    pub conditions: Vec<Condition>,
}

/// Effect of an access control entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    /// Allow the operations.
    Allow,
    /// Deny the operations.
    Deny,
}

/// Condition for access control.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Condition {
    /// IP address must match.
    IpAddress(String),
    /// Time must be within range.
    TimeRange { start: String, end: String },
    /// MFA must be present.
    MfaPresent,
    /// Custom condition.
    Custom { key: String, value: String },
}

/// Policy engine for evaluating key access.
pub struct PolicyEngine;

impl PolicyEngine {
    /// Check if an operation is allowed for a key.
    pub fn check_operation(
        entry: &KeyEntry,
        operation: Operation,
        _context: &OperationContext,
    ) -> KeyResult<()> {
        // Check key status first
        if !entry.status.is_usable() {
            return Err(KeyError::PolicyViolation(format!(
                "Key {} is not usable (status: {:?})",
                entry.key_id, entry.status
            )));
        }

        // Check algorithm compatibility with operation
        Self::check_algorithm_operation(entry.algorithm, operation)?;

        // Check usage limits
        // (In a real implementation, this would track daily/total usage)

        Ok(())
    }

    /// Check if an algorithm supports an operation.
    fn check_algorithm_operation(algorithm: Algorithm, operation: Operation) -> KeyResult<()> {
        let valid = match operation {
            Operation::Encrypt | Operation::Decrypt | Operation::Wrap | Operation::Unwrap => {
                matches!(
                    algorithm,
                    Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024
                )
            }
            Operation::Sign | Operation::Verify => matches!(
                algorithm,
                Algorithm::MlDsa44
                    | Algorithm::MlDsa65
                    | Algorithm::MlDsa87
                    | Algorithm::SlhDsaShake128s
                    | Algorithm::SlhDsaShake128f
                    | Algorithm::SlhDsaShake256s
                    | Algorithm::SlhDsaShake256f
            ),
            Operation::ExportPublic => true,
            Operation::ExportPrivate | Operation::Derive => true,
        };

        if valid {
            Ok(())
        } else {
            Err(KeyError::PolicyViolation(format!(
                "Algorithm {} does not support operation {:?}",
                algorithm, operation
            )))
        }
    }
}

/// Context for an operation request.
#[derive(Clone, Debug, Default)]
pub struct OperationContext {
    /// Requesting principal.
    pub principal: Option<String>,
    /// Source IP address.
    pub ip_address: Option<String>,
    /// MFA token present.
    pub mfa_present: bool,
    /// Additional attributes.
    pub attributes: std::collections::HashMap<String, String>,
}

impl OperationContext {
    /// Create a new operation context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the principal.
    pub fn with_principal(mut self, principal: impl Into<String>) -> Self {
        self.principal = Some(principal.into());
        self
    }

    /// Set the IP address.
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Set MFA present.
    pub fn with_mfa(mut self) -> Self {
        self.mfa_present = true;
        self
    }
}
