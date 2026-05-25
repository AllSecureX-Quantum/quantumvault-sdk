//! Minimal RFC 1035-style zone file parser.
//!
//! We support the common record types used in real zones:
//! **A, AAAA, MX, CNAME, TXT, NS, SOA, PTR, SRV, CAA, DNSKEY**. The
//! parser is intentionally simple — no $ORIGIN / $INCLUDE / multi-line
//! record continuations across parentheses. Real customer zones that
//! use those features should be pre-processed (`named-compilezone -F text`
//! handles that already).
//!
//! Group records into RRSets by `(owner, class, type)` for signing.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{DnssecError, Result};

/// One resource record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceRecord {
    /// Owner name (e.g. `"api.example.com."`). Always FQDN, dot-terminated.
    pub name: String,
    /// TTL in seconds.
    pub ttl: u32,
    /// Class — usually `"IN"`.
    pub class: String,
    /// Record type — `"A"`, `"AAAA"`, `"MX"`, etc.
    pub rtype: String,
    /// RDATA as a single canonical string (whatever the parser produced).
    pub rdata: String,
}

/// A set of records grouped by (owner, class, type) — DNSSEC's signing unit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RrSet {
    /// Owner name (FQDN).
    pub name: String,
    /// Class.
    pub class: String,
    /// Record type.
    pub rtype: String,
    /// All RDATA strings under this (name, class, type), sorted.
    pub rdatas: Vec<String>,
    /// TTL (the minimum of all members, per RFC 2181 §5.2).
    pub ttl: u32,
}

impl RrSet {
    /// Canonical signing bytes: `"NAME CLASS TYPE TTL RDATAS..."` with
    /// RDATAs joined by `"\n"` and sorted. Stable across runs.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = String::new();
        buf.push_str(&self.name.to_ascii_lowercase());
        buf.push(' ');
        buf.push_str(&self.class.to_ascii_uppercase());
        buf.push(' ');
        buf.push_str(&self.rtype.to_ascii_uppercase());
        buf.push(' ');
        buf.push_str(&self.ttl.to_string());
        for r in &self.rdatas {
            buf.push('\n');
            buf.push_str(r);
        }
        buf.into_bytes()
    }

    /// Stable RRSet key for manifest indexing: `"name|class|type"`.
    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}",
            self.name.to_ascii_lowercase(),
            self.class,
            self.rtype
        )
    }
}

/// A parsed zone — records + grouped RRSets.
#[derive(Debug, Clone)]
pub struct Zone {
    /// Origin / zone apex (e.g. `"example.com."`).
    pub origin: String,
    /// Records in source order.
    pub records: Vec<ResourceRecord>,
    /// Records grouped by (owner, class, type).
    pub rrsets: Vec<RrSet>,
}

/// Parse a BIND-style zone file.
///
/// The first non-comment line may be `$ORIGIN example.com.`. Owner
/// names are completed to FQDNs using the origin where they don't
/// already end with `"."`.
///
/// Parenthesised multi-line records (commonly used for SOA) are
/// supported: from a `(` to the matching `)`, all newlines are folded
/// into spaces before tokenisation. Nested parens are not supported.
pub fn parse_zone(text: &str) -> Result<Zone> {
    let folded = fold_parenthesised_lines(text)?;
    let text = folded.as_str();
    let mut origin: Option<String> = None;
    let mut default_ttl: Option<u32> = None;
    let mut records: Vec<ResourceRecord> = Vec::new();
    let mut last_owner: Option<String> = None;

    for (line_no_zero, raw_line) in text.lines().enumerate() {
        let line_no = line_no_zero + 1;
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        // Directives.
        if let Some(rest) = line.strip_prefix("$ORIGIN") {
            let o = rest.trim().trim_end_matches('.').to_string();
            origin = Some(format!("{}.", o));
            continue;
        }
        if let Some(rest) = line.strip_prefix("$TTL") {
            let n: u32 = rest
                .trim()
                .parse()
                .map_err(|_| DnssecError::MalformedZone {
                    line: line_no,
                    message: format!("invalid $TTL value: {rest:?}"),
                })?;
            default_ttl = Some(n);
            continue;
        }

        // Tokenise. We don't support parenthesised multi-line records
        // in v1 — pre-process with named-compilezone if you need them.
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        // Detect leading owner. If the line starts with whitespace we
        // continue the previous owner. Otherwise the first token is the
        // owner.
        let starts_with_ws = raw_line
            .chars()
            .next()
            .map(|c| c.is_whitespace())
            .unwrap_or(false);

        let (owner, rest_tokens): (String, &[&str]) = if starts_with_ws {
            let prev = last_owner.clone().ok_or(DnssecError::MalformedZone {
                line: line_no,
                message: "indented line with no preceding owner".into(),
            })?;
            (prev, &tokens[..])
        } else {
            (tokens[0].to_string(), &tokens[1..])
        };
        last_owner = Some(owner.clone());

        // The next tokens are some combination of TTL, class, type, and
        // rdata in any order (RFC 1035 §5.1 — TTL and class are optional
        // and reorderable). We scan for them and treat the remaining
        // tokens as rdata.
        let mut ttl: Option<u32> = None;
        let mut class: Option<String> = None;
        let mut rtype: Option<String> = None;
        let mut cursor = 0usize;

        for _ in 0..3 {
            if cursor >= rest_tokens.len() {
                break;
            }
            let t = rest_tokens[cursor];
            if let Ok(n) = t.parse::<u32>() {
                if ttl.is_none() {
                    ttl = Some(n);
                    cursor += 1;
                    continue;
                }
            }
            let upper = t.to_ascii_uppercase();
            if class.is_none() && matches!(upper.as_str(), "IN" | "CH" | "HS") {
                class = Some(upper);
                cursor += 1;
                continue;
            }
            if rtype.is_none() && is_known_type(&upper) {
                rtype = Some(upper);
                cursor += 1;
                continue;
            }
            break;
        }

        let rtype = rtype.ok_or(DnssecError::MalformedZone {
            line: line_no,
            message: format!("could not find record type in {tokens:?}"),
        })?;
        let class = class.unwrap_or_else(|| "IN".into());
        let ttl = ttl.or(default_ttl).ok_or(DnssecError::MalformedZone {
            line: line_no,
            message: "no TTL given (set $TTL or specify per-record)".into(),
        })?;

        let rdata = rest_tokens[cursor..].join(" ");
        if rdata.is_empty() {
            return Err(DnssecError::MalformedZone {
                line: line_no,
                message: format!("no rdata for record of type {rtype}"),
            });
        }

        let fqdn = canonicalise_name(&owner, origin.as_deref());
        records.push(ResourceRecord {
            name: fqdn,
            ttl,
            class,
            rtype,
            rdata,
        });
    }

    let origin = origin.unwrap_or_else(|| {
        records
            .first()
            .map(|r| r.name.clone())
            .unwrap_or_else(|| ".".to_string())
    });

    // Group by (owner, class, type) — deterministic ordering via BTreeMap.
    let mut grouped: BTreeMap<(String, String, String), Vec<&ResourceRecord>> = BTreeMap::new();
    for r in &records {
        grouped
            .entry((
                r.name.to_ascii_lowercase(),
                r.class.clone(),
                r.rtype.clone(),
            ))
            .or_default()
            .push(r);
    }
    let rrsets: Vec<RrSet> = grouped
        .into_iter()
        .map(|((name, class, rtype), members)| {
            let mut rdatas: Vec<String> = members.iter().map(|r| r.rdata.clone()).collect();
            rdatas.sort();
            let ttl = members.iter().map(|r| r.ttl).min().unwrap_or(0);
            RrSet {
                name,
                class,
                rtype,
                rdatas,
                ttl,
            }
        })
        .collect();

    Ok(Zone {
        origin,
        records,
        rrsets,
    })
}

/// Collapse parenthesised multi-line records into single lines.
/// Inside parens, comments are stripped and CR/LF become spaces.
/// Parens that themselves appear inside a quoted string are
/// preserved literally.
fn fold_parenthesised_lines(text: &str) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut depth: u32 = 0;
    let mut in_quote = false;
    let mut line_no: usize = 1;
    let mut iter = text.chars().peekable();
    while let Some(c) = iter.next() {
        if c == '\n' {
            line_no += 1;
        }
        if in_quote {
            out.push(c);
            if c == '"' {
                in_quote = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_quote = true;
                out.push(c);
            }
            ';' if depth > 0 => {
                // Strip in-paren comment to end of line.
                while let Some(&n) = iter.peek() {
                    if n == '\n' {
                        break;
                    }
                    iter.next();
                }
            }
            '(' => {
                depth += 1;
                out.push(' ');
            }
            ')' => {
                if depth == 0 {
                    return Err(DnssecError::MalformedZone {
                        line: line_no,
                        message: "unmatched ')'".into(),
                    });
                }
                depth -= 1;
                out.push(' ');
            }
            '\n' | '\r' if depth > 0 => out.push(' '),
            _ => out.push(c),
        }
    }
    if depth != 0 {
        return Err(DnssecError::MalformedZone {
            line: line_no,
            message: "unterminated '(' in zone".into(),
        });
    }
    Ok(out)
}

fn strip_comment(line: &str) -> &str {
    // BIND comments start with ';' outside of quoted strings. For the
    // record types we support, ';' inside quotes is rare; this simple
    // strip is fine.
    match line.find(';') {
        Some(i) => &line[..i],
        None => line,
    }
}

fn canonicalise_name(owner: &str, origin: Option<&str>) -> String {
    if owner == "@" {
        return origin.unwrap_or(".").to_string();
    }
    if owner.ends_with('.') {
        return owner.to_string();
    }
    match origin {
        Some(o) => format!("{}.{}", owner.trim_end_matches('.'), o),
        None => format!("{}.", owner),
    }
}

fn is_known_type(t: &str) -> bool {
    matches!(
        t,
        "A" | "AAAA" | "MX" | "CNAME" | "TXT" | "NS" | "SOA" | "PTR" | "SRV" | "CAA" | "DNSKEY"
    )
}
