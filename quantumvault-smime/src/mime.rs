//! Minimal RFC 5322 + multipart MIME helpers.
//!
//! We avoid pulling a full MIME parser because the surface we care about
//! is tiny: split headers from body, find/emit a `multipart/signed`
//! boundary, base64-encode/decode a signature attachment. Anything more
//! sophisticated (RFC 2047 encoded-words, quoted-printable, deep nesting)
//! is out of scope — by design the input is the customer's pre-encoded
//! outgoing message.

use rand::RngCore;

use crate::error::{Result, SmimeError};

/// Header/body split of an RFC 5322 message.
#[derive(Debug, Clone)]
pub struct MimeSplit {
    /// Raw header block (everything before the blank line), including the
    /// terminating CRLF.
    pub headers: Vec<u8>,
    /// Raw body bytes (everything after the blank line separator). May
    /// itself be multipart.
    pub body: Vec<u8>,
}

/// A single MIME body part: a (possibly empty) header block + body bytes.
#[derive(Debug, Clone)]
pub struct MimePart {
    /// Header lines, joined by CRLF. May be empty.
    pub headers: Vec<u8>,
    /// Body bytes for this part.
    pub body: Vec<u8>,
}

/// Find the header/body separator. Accepts CRLF CRLF or LF LF.
pub fn split_headers_body(input: &[u8]) -> Result<MimeSplit> {
    // Prefer CRLF CRLF.
    if let Some(idx) = find_subseq(input, b"\r\n\r\n") {
        return Ok(MimeSplit {
            headers: input[..idx + 2].to_vec(),
            body: input[idx + 4..].to_vec(),
        });
    }
    // Fall back to LF LF.
    if let Some(idx) = find_subseq(input, b"\n\n") {
        return Ok(MimeSplit {
            headers: input[..idx + 1].to_vec(),
            body: input[idx + 2..].to_vec(),
        });
    }
    Err(SmimeError::InvalidMessage(
        "no blank line separating headers and body",
    ))
}

/// Look up the value of a specific header (case-insensitive). Returns
/// `None` if missing, the *unfolded* value (single line) otherwise.
pub fn header_value(headers: &[u8], name: &str) -> Option<String> {
    let needle = name.to_ascii_lowercase();
    let text = std::str::from_utf8(headers).ok()?;
    let mut current: Option<String> = None;
    for line in text.split_inclusive('\n') {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(ref mut acc) = current {
                acc.push_str(line.trim_end_matches(['\r', '\n']));
            }
            continue;
        }
        // New header line — emit the previous one if it matched.
        if let Some(acc) = current.take() {
            if let Some((n, v)) = acc.split_once(':') {
                if n.trim().eq_ignore_ascii_case(&needle) {
                    return Some(v.trim().to_string());
                }
            }
        }
        current = Some(line.trim_end_matches(['\r', '\n']).to_string());
    }
    // Tail.
    if let Some(acc) = current {
        if let Some((n, v)) = acc.split_once(':') {
            if n.trim().eq_ignore_ascii_case(&needle) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Extract a parameter from a Content-Type header value, e.g.
/// `multipart/signed; boundary="xxx"` → `param_value(value, "boundary")` →
/// `Some("xxx")`.
pub fn param_value(header_value: &str, name: &str) -> Option<String> {
    let needle = name.to_ascii_lowercase();
    for part in header_value.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim().eq_ignore_ascii_case(&needle) {
                let v = v.trim();
                // Strip surrounding quotes if present.
                let v = v.strip_prefix('"').unwrap_or(v);
                let v = v.strip_suffix('"').unwrap_or(v);
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Split a multipart MIME body into its parts.
///
/// `body` is what comes after the headers (i.e. starts with the preamble,
/// then `--boundary\r\n`, then the first part). `boundary` is the value
/// from the Content-Type header — without the leading `--`.
pub fn split_multipart(body: &[u8], boundary: &str) -> Result<Vec<MimePart>> {
    let opener_crlf = format!("--{}\r\n", boundary);
    let opener_lf = format!("--{}\n", boundary);
    let separator_crlf = format!("\r\n--{}\r\n", boundary);
    let separator_lf = format!("\n--{}\n", boundary);
    let closer_crlf = format!("\r\n--{}--", boundary);
    let closer_lf = format!("\n--{}--", boundary);

    // Find the start of the first part. The body may have a "preamble"
    // before the first boundary — discard it.
    let start = if let Some(i) = find_subseq(body, opener_crlf.as_bytes()) {
        i + opener_crlf.len()
    } else if let Some(i) = find_subseq(body, opener_lf.as_bytes()) {
        i + opener_lf.len()
    } else {
        return Err(SmimeError::MultipartMalformed(
            "first boundary not found in body",
        ));
    };

    // Find the closing boundary.
    let end = find_subseq(body, closer_crlf.as_bytes())
        .or_else(|| find_subseq(body, closer_lf.as_bytes()))
        .ok_or(SmimeError::MultipartMalformed("closing boundary not found"))?;

    let inner = &body[start..end];

    // Split the inner content on the inter-part separator.
    let mut parts_bytes: Vec<&[u8]> = Vec::new();
    let mut cursor = inner;
    loop {
        let next = find_subseq(cursor, separator_crlf.as_bytes())
            .map(|i| (i, separator_crlf.len()))
            .or_else(|| {
                find_subseq(cursor, separator_lf.as_bytes()).map(|i| (i, separator_lf.len()))
            });
        match next {
            Some((i, sep_len)) => {
                parts_bytes.push(&cursor[..i]);
                cursor = &cursor[i + sep_len..];
            }
            None => {
                parts_bytes.push(cursor);
                break;
            }
        }
    }

    let mut parts = Vec::with_capacity(parts_bytes.len());
    for p in parts_bytes {
        let s = split_headers_body(p)?;
        parts.push(MimePart {
            headers: s.headers,
            body: s.body,
        });
    }
    Ok(parts)
}

/// Build a `multipart/signed` envelope around a body and a signature blob.
///
/// `original_message_bytes` is the full original RFC 5322 message (headers
/// + body). Its headers are preserved verbatim except for the
/// `Content-Type`, `Content-Transfer-Encoding`, and `MIME-Version` headers
/// which are replaced with multipart/signed equivalents.
pub fn wrap_multipart_signed(
    original_message_bytes: &[u8],
    signature_envelope_json: &[u8],
) -> Result<Vec<u8>> {
    let split = split_headers_body(original_message_bytes)?;

    // Preserve the original Content-Type to apply to the inner body part.
    let original_content_type = header_value(&split.headers, "Content-Type")
        .unwrap_or_else(|| "text/plain; charset=utf-8".to_string());

    let boundary = random_boundary();
    let outer_content_type = format!(
        "multipart/signed; protocol=\"application/pqc-signature\"; micalg=\"sha3-256\"; boundary=\"{}\"",
        boundary
    );

    // Build new outer headers: keep everything except the headers we're
    // about to replace.
    let mut new_headers: Vec<u8> = Vec::new();
    for line in split_header_lines(&split.headers) {
        let s = String::from_utf8_lossy(&line);
        let lower = s.to_ascii_lowercase();
        if lower.starts_with("content-type:")
            || lower.starts_with("content-transfer-encoding:")
            || lower.starts_with("mime-version:")
        {
            continue;
        }
        new_headers.extend_from_slice(&line);
    }
    new_headers.extend_from_slice(b"MIME-Version: 1.0\r\n");
    new_headers.extend_from_slice(format!("Content-Type: {}\r\n", outer_content_type).as_bytes());

    // Build the body: preamble + part1 (original body wrapped with its
    // original Content-Type) + part2 (signature attachment).
    let preamble =
        b"This is a multipart message signed with NIST FIPS 204 ML-DSA (post-quantum).\r\n\r\n";

    let part1_headers = format!("Content-Type: {}\r\n\r\n", original_content_type);

    let mut part2 = String::new();
    part2.push_str("Content-Type: application/pqc-signature; name=\"signature.pqc\"\r\n");
    part2.push_str("Content-Transfer-Encoding: base64\r\n");
    part2.push_str("Content-Disposition: attachment; filename=\"signature.pqc\"\r\n\r\n");

    let sig_b64 = base64_wrap_76(signature_envelope_json);

    let mut out = new_headers;
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(preamble);
    out.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    out.extend_from_slice(part1_headers.as_bytes());
    out.extend_from_slice(&split.body);
    out.extend_from_slice(format!("\r\n--{}\r\n", boundary).as_bytes());
    out.extend_from_slice(part2.as_bytes());
    out.extend_from_slice(sig_b64.as_bytes());
    out.extend_from_slice(format!("\r\n--{}--\r\n", boundary).as_bytes());
    Ok(out)
}

// =====================================================================
// Internal helpers
// =====================================================================

fn find_subseq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn random_boundary() -> String {
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
    format!("qvsmime-{}", B64URL.encode(bytes))
}

/// Split a header block into individual logical lines, **unfolding** any
/// continuation lines. Each emitted entry ends with CRLF.
fn split_header_lines(headers: &[u8]) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(headers);
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    for line in text.split_inclusive('\n') {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation — append to the current line.
            current.extend_from_slice(line.as_bytes());
            continue;
        }
        if !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
        current.extend_from_slice(line.as_bytes());
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// base64 encode and wrap at 76 chars per line (RFC 2045).
fn base64_wrap_76(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let encoded = B64.encode(bytes);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 76 * 2);
    for chunk in encoded.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push_str("\r\n");
    }
    // Trim the trailing CRLF — the caller adds one before the closing boundary.
    if out.ends_with("\r\n") {
        out.truncate(out.len() - 2);
    }
    out
}

/// Base64-decode a body that may contain CRLF/LF/whitespace line wraps.
pub(crate) fn base64_decode_loose(s: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let stripped: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    B64.decode(stripped.as_bytes())
        .map_err(|e| SmimeError::Base64(e.to_string()))
}
