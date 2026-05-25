//! Pure JWT-verification function (testable without spinning a server).

use quantumvault_core::VerifyingKey;
use quantumvault_jose::{decode_with_validation, DecodedJwt, Error, Validation};

/// Outcome of trying to verify an incoming Authorization header.
#[derive(Debug)]
pub enum JwtOutcome {
    /// Token was present, well-formed, and verified cleanly.
    Ok(DecodedJwt),
    /// `Authorization` header missing or didn't start with `Bearer `.
    MissingBearer,
    /// Token failed verification — categorised by the underlying jose error.
    Rejected(Error),
}

/// Verify a bearer token. Pass the value of the `Authorization` header
/// (or `None` if absent) plus the verifying key + validation policy.
pub fn verify_jwt(
    authorization_header: Option<&str>,
    verifying_key: &VerifyingKey,
    policy: &Validation,
) -> JwtOutcome {
    let token = match extract_bearer(authorization_header) {
        Some(t) => t,
        None => return JwtOutcome::MissingBearer,
    };

    match decode_with_validation(token, verifying_key, policy) {
        Ok(decoded) => JwtOutcome::Ok(decoded),
        Err(e) => JwtOutcome::Rejected(e),
    }
}

/// Pull the JWT out of an `Authorization: Bearer <jwt>` header value.
fn extract_bearer(header: Option<&str>) -> Option<&str> {
    let h = header?;
    let h = h.trim();
    // Case-insensitive `Bearer` prefix.
    if h.len() < 7 {
        return None;
    }
    let (scheme, rest) = h.split_at(6);
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = rest.trim_start();
    if token.is_empty() {
        return None;
    }
    Some(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_bearer_handles_well_formed_header() {
        assert_eq!(
            extract_bearer(Some("Bearer abc.def.ghi")),
            Some("abc.def.ghi")
        );
        assert_eq!(extract_bearer(Some("bearer abc")), Some("abc"));
        assert_eq!(
            extract_bearer(Some("BEARER  spaced.token")),
            Some("spaced.token")
        );
    }

    #[test]
    fn extract_bearer_rejects_missing_or_malformed() {
        assert_eq!(extract_bearer(None), None);
        assert_eq!(extract_bearer(Some("")), None);
        assert_eq!(extract_bearer(Some("Basic xyz")), None);
        assert_eq!(extract_bearer(Some("Bearer")), None);
        assert_eq!(extract_bearer(Some("Bearer ")), None);
    }
}
