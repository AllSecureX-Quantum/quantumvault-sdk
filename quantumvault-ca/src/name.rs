//! X.500 Distinguished Name — minimal subset matching what real X.509
//! certs carry in the Subject and Issuer fields.

use serde::{Deserialize, Serialize};

/// X.500 Distinguished Name (subset).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DistinguishedName {
    /// Common Name (CN). Required.
    pub cn: String,
    /// Organisation (O). Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub o: Option<String>,
    /// Organisational Unit (OU). Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ou: Option<String>,
    /// Country (C). Two-letter ISO 3166 code, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub c: Option<String>,
    /// Locality (L). Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l: Option<String>,
    /// State / Province (ST). Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub st: Option<String>,
    /// Email address. Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

impl DistinguishedName {
    /// Construct from a Common Name; all other fields blank.
    pub fn cn(cn: impl Into<String>) -> Self {
        Self {
            cn: cn.into(),
            o: None,
            ou: None,
            c: None,
            l: None,
            st: None,
            email: None,
        }
    }

    /// Builder: set Organisation.
    pub fn with_o(mut self, o: impl Into<String>) -> Self {
        self.o = Some(o.into());
        self
    }
    /// Builder: set Organisational Unit.
    pub fn with_ou(mut self, ou: impl Into<String>) -> Self {
        self.ou = Some(ou.into());
        self
    }
    /// Builder: set Country (ISO 3166 two-letter).
    pub fn with_c(mut self, c: impl Into<String>) -> Self {
        self.c = Some(c.into());
        self
    }
    /// Builder: set Locality.
    pub fn with_l(mut self, l: impl Into<String>) -> Self {
        self.l = Some(l.into());
        self
    }
    /// Builder: set State.
    pub fn with_st(mut self, st: impl Into<String>) -> Self {
        self.st = Some(st.into());
        self
    }
    /// Builder: set email address.
    pub fn with_email(mut self, e: impl Into<String>) -> Self {
        self.email = Some(e.into());
        self
    }

    /// Render as an OpenSSL-style DN string, e.g.
    /// `CN=AllSecureX Root CA, O=Quantum Cybertech, C=IN`.
    pub fn to_display(&self) -> String {
        let mut parts: Vec<String> = vec![format!("CN={}", self.cn)];
        if let Some(o) = &self.o {
            parts.push(format!("O={o}"));
        }
        if let Some(ou) = &self.ou {
            parts.push(format!("OU={ou}"));
        }
        if let Some(l) = &self.l {
            parts.push(format!("L={l}"));
        }
        if let Some(st) = &self.st {
            parts.push(format!("ST={st}"));
        }
        if let Some(c) = &self.c {
            parts.push(format!("C={c}"));
        }
        if let Some(email) = &self.email {
            parts.push(format!("emailAddress={email}"));
        }
        parts.join(", ")
    }
}

impl std::fmt::Display for DistinguishedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_display())
    }
}
