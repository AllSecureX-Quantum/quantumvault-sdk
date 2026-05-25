//! JWS compact serialisation (RFC 7515 §3.1) — `header.payload.signature`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use chrono::Utc;

use quantumvault_core::api::{sign as core_sign, verify as core_verify};
use quantumvault_core::{Config, SecurityLevel, Signature, SigningKey, VerifyingKey};

use crate::algorithm::Algorithm;
use crate::claims::Claims;
use crate::error::{Error, Result};
use crate::header::Header;

/// Encode a JWS compact serialisation: `BASE64URL(header) . BASE64URL(payload) . BASE64URL(signature)`.
///
/// The signature covers `BASE64URL(header) || "." || BASE64URL(payload)` (the
/// "signing input" per RFC 7515 §5.1 step 5).
///
/// `alg` and `signing_key.algorithm` must match. Mismatches return an error
/// rather than silently coercing.
pub fn encode(claims: &Claims, alg: Algorithm, signing_key: &SigningKey) -> Result<String> {
    if signing_key.algorithm != alg.to_core() {
        return Err(Error::AlgorithmNotAllowed(format!(
            "header alg={} but signing key is {}",
            alg, signing_key.algorithm,
        )));
    }

    let header = Header::new(alg);
    let header_b64 = B64URL.encode(serde_json::to_vec(&header)?);
    let payload_b64 = B64URL.encode(serde_json::to_vec(claims)?);

    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let cfg = config_for(alg);
    let signature = core_sign::sign_message(signing_input.as_bytes(), signing_key, &cfg)?;
    let sig_b64 = B64URL.encode(&signature.bytes);

    Ok(format!("{}.{}", signing_input, sig_b64))
}

/// Encode a JWS with a caller-supplied header — useful for setting `kid`
/// or `cty`. The header's `alg` must match `signing_key.algorithm`.
pub fn encode_with_header(
    header: Header,
    claims: &Claims,
    signing_key: &SigningKey,
) -> Result<String> {
    if signing_key.algorithm != header.alg.to_core() {
        return Err(Error::AlgorithmNotAllowed(format!(
            "header alg={} but signing key is {}",
            header.alg, signing_key.algorithm,
        )));
    }
    let header_b64 = B64URL.encode(serde_json::to_vec(&header)?);
    let payload_b64 = B64URL.encode(serde_json::to_vec(claims)?);
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let cfg = config_for(header.alg);
    let signature = core_sign::sign_message(signing_input.as_bytes(), signing_key, &cfg)?;
    let sig_b64 = B64URL.encode(&signature.bytes);
    Ok(format!("{}.{}", signing_input, sig_b64))
}

/// Decoded JWT — header, claims, and the bytes that produced the signature.
#[derive(Debug, Clone)]
pub struct DecodedJwt {
    /// The JWS protected header.
    pub header: Header,
    /// The claims set.
    pub claims: Claims,
}

/// Validation policy applied during [`decode`].
///
/// By default `decode` verifies the signature, enforces `exp` if present,
/// and enforces `nbf` if present. To require `iss` or `aud` match exact
/// values, set them here.
#[derive(Debug, Clone, Default)]
pub struct Validation {
    /// Required issuer (`iss`). If `Some`, the claim must match exactly.
    pub expected_issuer: Option<String>,
    /// Required audience (`aud`). If `Some`, the claim must contain this value.
    pub expected_audience: Option<String>,
    /// Allowed algorithms. If empty, all [`Algorithm`] variants are accepted.
    pub allowed_algorithms: Vec<Algorithm>,
    /// Clock skew tolerance in seconds applied to `exp` and `nbf` checks.
    /// Default: 0 (strict).
    pub leeway_seconds: i64,
    /// If `true`, missing `exp` is treated as an error. Default: `false`.
    pub require_exp: bool,
}

impl Validation {
    /// Strict-mode validation: require `exp`, no clock skew tolerance.
    pub fn strict() -> Self {
        Self {
            require_exp: true,
            ..Self::default()
        }
    }

    /// Require the issuer to match.
    pub fn with_issuer(mut self, iss: impl Into<String>) -> Self {
        self.expected_issuer = Some(iss.into());
        self
    }

    /// Require the audience to include this value.
    pub fn with_audience(mut self, aud: impl Into<String>) -> Self {
        self.expected_audience = Some(aud.into());
        self
    }

    /// Restrict allowed algorithms. Anything else in the header is rejected.
    pub fn with_algorithms(mut self, algs: Vec<Algorithm>) -> Self {
        self.allowed_algorithms = algs;
        self
    }

    /// Allow `leeway` seconds of clock skew for `exp` and `nbf` checks.
    pub fn with_leeway_seconds(mut self, leeway: i64) -> Self {
        self.leeway_seconds = leeway;
        self
    }
}

/// Decode and verify a JWS compact-serialised token with default validation.
pub fn decode(token: &str, verifying_key: &VerifyingKey) -> Result<DecodedJwt> {
    decode_with_validation(token, verifying_key, &Validation::default())
}

/// Decode and verify with a caller-supplied policy.
pub fn decode_with_validation(
    token: &str,
    verifying_key: &VerifyingKey,
    validation: &Validation,
) -> Result<DecodedJwt> {
    // 1. Split into the three parts.
    let mut parts = token.splitn(3, '.');
    let header_b64 = parts.next().ok_or(Error::Malformed("missing header"))?;
    let payload_b64 = parts.next().ok_or(Error::Malformed("missing payload"))?;
    let sig_b64 = parts.next().ok_or(Error::Malformed("missing signature"))?;
    if parts.next().is_some() {
        return Err(Error::Malformed("more than 3 segments"));
    }

    // 2. Decode the header and check `alg`.
    let header_bytes = B64URL.decode(header_b64)?;
    let header: Header = serde_json::from_slice(&header_bytes)?;
    if !validation.allowed_algorithms.is_empty()
        && !validation.allowed_algorithms.contains(&header.alg)
    {
        return Err(Error::AlgorithmNotAllowed(header.alg.to_string()));
    }
    if header.alg.to_core() != verifying_key.algorithm {
        return Err(Error::AlgorithmNotAllowed(format!(
            "header alg={} but verifying key is {}",
            header.alg, verifying_key.algorithm,
        )));
    }

    // 3. Verify signature over `header.payload` BEFORE trusting the body.
    let sig_bytes = B64URL.decode(sig_b64)?;
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature = Signature {
        bytes: sig_bytes,
        algorithm: header.alg.to_core(),
        key_id: verifying_key.key_id.clone(),
        signed_at: 0, // not consulted by verifier
    };
    let cfg = config_for(header.alg);
    let ok =
        core_verify::verify_signature(signing_input.as_bytes(), &signature, verifying_key, &cfg)?;
    if !ok {
        return Err(Error::InvalidSignature);
    }

    // 4. Now (and only now) parse the claims.
    let payload_bytes = B64URL.decode(payload_b64)?;
    let claims: Claims = serde_json::from_slice(&payload_bytes)?;

    // 5. Time-based validation.
    let now = Utc::now().timestamp();
    if validation.require_exp && claims.exp.is_none() {
        return Err(Error::Expired);
    }
    if let Some(exp) = claims.exp {
        if now > exp + validation.leeway_seconds {
            return Err(Error::Expired);
        }
    }
    if let Some(nbf) = claims.nbf {
        if now + validation.leeway_seconds < nbf {
            return Err(Error::NotYetValid);
        }
    }

    // 6. Identity validation.
    if let Some(expected) = &validation.expected_issuer {
        match &claims.iss {
            Some(actual) if actual == expected => {}
            _ => return Err(Error::IssuerMismatch),
        }
    }
    if let Some(expected) = &validation.expected_audience {
        let ok = claims
            .aud
            .as_ref()
            .map(|a| a.contains(expected))
            .unwrap_or(false);
        if !ok {
            return Err(Error::AudienceMismatch);
        }
    }

    Ok(DecodedJwt { header, claims })
}

/// Construct a `Config` matching the algorithm's security level so the
/// core API accepts the operation.
fn config_for(alg: Algorithm) -> Config {
    let lvl = match alg {
        Algorithm::MlDsa44 => SecurityLevel::Level2,
        Algorithm::MlDsa65 => SecurityLevel::Level3,
        Algorithm::MlDsa87 => SecurityLevel::Level5,
    };
    // Builder is infallible for these inputs; unwrap is sound.
    Config::builder()
        .security_level(lvl)
        .build()
        .expect("valid config")
}
