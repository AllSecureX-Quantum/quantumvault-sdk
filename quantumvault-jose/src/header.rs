//! JWS protected header.

use serde::{Deserialize, Serialize};

use crate::algorithm::Algorithm;

/// JWS protected header (RFC 7515 §4).
///
/// Only the fields we actually emit / accept are typed; everything else is
/// preserved through an `extras` bag so callers can carry custom headers
/// like `kid` or `cty` without losing fidelity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Header {
    /// Token type. We default to `"JWT"` when not provided.
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Algorithm — one of the values in [`Algorithm`].
    pub alg: Algorithm,

    /// Key ID. Optional but recommended when verifiers may rotate keys.
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Content type (`cty`). Often unset.
    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,
}

impl Header {
    /// Construct a header for the given algorithm with `typ = JWT`.
    pub fn new(alg: Algorithm) -> Self {
        Self {
            typ: Some("JWT".into()),
            alg,
            kid: None,
            cty: None,
        }
    }

    /// Set the key ID. Useful for verifiers that consult a JWKS.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Set the content type.
    pub fn with_cty(mut self, cty: impl Into<String>) -> Self {
        self.cty = Some(cty.into());
        self
    }
}
