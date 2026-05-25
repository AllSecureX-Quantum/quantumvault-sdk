//! Standard and custom JWT claims (RFC 7519 §4).

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// A token audience, either a single string or a list of strings
/// (RFC 7519 allows both).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Audience {
    /// Single-audience case (the common one).
    Single(String),
    /// Multi-audience case.
    Multi(Vec<String>),
}

impl Audience {
    /// True if `expected` matches the audience (any of, for multi).
    pub fn contains(&self, expected: &str) -> bool {
        match self {
            Audience::Single(s) => s == expected,
            Audience::Multi(v) => v.iter().any(|s| s == expected),
        }
    }
}

/// JWT claims set.
///
/// Standard registered claims are typed (RFC 7519 §4.1). Custom claims
/// land in [`Claims::extras`] and are preserved through the round trip.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Claims {
    /// `iss` — issuer.
    #[serde(rename = "iss", skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// `sub` — subject (usually the user/principal ID).
    #[serde(rename = "sub", skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// `aud` — audience(s) the token is intended for.
    #[serde(rename = "aud", skip_serializing_if = "Option::is_none")]
    pub aud: Option<Audience>,

    /// `exp` — expiration time as Unix seconds.
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// `nbf` — not-before time as Unix seconds.
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// `iat` — issued-at time as Unix seconds.
    #[serde(rename = "iat", skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// `jti` — JWT ID. Recommended for revocation tracking.
    #[serde(rename = "jti", skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Custom claims (anything not in the registered set).
    #[serde(flatten)]
    pub extras: BTreeMap<String, Value>,
}

impl Claims {
    /// Start with an empty claims set.
    pub fn new() -> Self {
        Self::default()
    }

    // --- builders ---------------------------------------------------------

    /// Set the `iss` claim.
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    /// Set the `sub` claim.
    pub fn subject(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    /// Set the `aud` claim to a single audience.
    pub fn audience(mut self, aud: impl Into<String>) -> Self {
        self.aud = Some(Audience::Single(aud.into()));
        self
    }

    /// Set the `aud` claim to a multi-audience list.
    pub fn audiences<I, S>(mut self, auds: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.aud = Some(Audience::Multi(auds.into_iter().map(Into::into).collect()));
        self
    }

    /// Set `iat` (issued-at) to the supplied instant.
    pub fn issued_at(mut self, when: DateTime<Utc>) -> Self {
        self.iat = Some(when.timestamp());
        self
    }

    /// Set `iat` to now.
    pub fn issued_now(self) -> Self {
        let now = Utc::now();
        self.issued_at(now)
    }

    /// Set `exp` (expiry) to the supplied instant.
    pub fn expiry(mut self, when: DateTime<Utc>) -> Self {
        self.exp = Some(when.timestamp());
        self
    }

    /// Set `exp` to `now + d`. Convenience for the common case.
    pub fn expiry_in(self, d: Duration) -> Self {
        self.expiry(Utc::now() + d)
    }

    /// Set `nbf` (not-before).
    pub fn not_before(mut self, when: DateTime<Utc>) -> Self {
        self.nbf = Some(when.timestamp());
        self
    }

    /// Set the JWT ID (`jti`).
    pub fn jwt_id(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }

    /// Attach a custom claim. Overwrites any existing claim with the
    /// same name.
    pub fn with_claim(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extras.insert(name.into(), value.into());
        self
    }

    // --- accessors (return references where cheap, owned where ergonomic)

    /// Get the issuer claim.
    pub fn issuer_str(&self) -> Option<&str> {
        self.iss.as_deref()
    }

    /// Get the subject claim.
    pub fn subject_str(&self) -> Option<&str> {
        self.sub.as_deref()
    }

    /// Get the audience claim.
    pub fn audience_ref(&self) -> Option<&Audience> {
        self.aud.as_ref()
    }

    /// Read a custom claim by name.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.extras.get(name)
    }
}
