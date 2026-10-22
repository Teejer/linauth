//! Account model + `otpauth://` parsing, including WinAuth export quirks:
//! - `+` in the label means a space (.NET `HttpUtility.UrlEncode` behaviour)
//! - base32 secrets may be unpadded
//! - WinAuth extras we preserve but do not interpret: `icon=`, `serial=`,
//!   `deviceid=`, `data=`

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::totp::Algorithm;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Totp,
    Hotp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub kind: Kind,
    pub issuer: String,
    pub label: String,
    pub secret: Vec<u8>,
    #[serde(default = "default_digits")]
    pub digits: u32,
    #[serde(default = "default_algo")]
    pub algorithm: Algorithm,
    #[serde(default = "default_period")]
    pub period: u64,
    /// only for HOTP
    #[serde(default)]
    pub counter: u64,
    /// raw extra params preserved for round-tripping (icon, serial, ...)
    #[serde(default)]
    pub extra: BTreeMap<String, String>,
}

fn default_digits() -> u32 {
    6
}
fn default_algo() -> Algorithm {
    Algorithm::Sha1
}
fn default_period() -> u64 {
    30
}

impl Account {
    /// "Issuer — label" for display; falls back gracefully.
    pub fn display_name(&self) -> String {
        match (self.issuer.as_str(), self.label.as_str()) {
            ("", l) => l.to_string(),
            (i, "") => i.to_string(),
            (i, l) => format!("{i} \u{2014} {l}"),
        }
    }

    /// Re-serialise to an `otpauth://` URI (WinAuth-compatible).
    pub fn to_uri(&self) -> String {
        use crate::uri;
        let mut q = format!(
            "secret={}&digits={}",
            uri::encode_secret_base32(&self.secret),
            self.digits
        );
        if !self.issuer.is_empty() {
            q += &format!("&issuer={}", urlencoding::encode(&self.issuer));
        }
        if self.algorithm != Algorithm::Sha1 {
            q += &format!("&algorithm={}", self.algorithm.as_str());
        }
        match self.kind {
            Kind::Totp => {
                if self.period != 30 {
                    q += &format!("&period={}", self.period);
                }
            }
            Kind::Hotp => q += &format!("&counter={}", self.counter),
        }
        for (k, v) in &self.extra {
            q += &format!("&{k}={}", urlencoding::encode(v));
        }
        let label_path = urlencoding::encode(&self.label);
        format!("otpauth://{}{label_path}?{q}", kind_path(self.kind))
    }
}

fn kind_path(k: Kind) -> &'static str {
    match k {
        Kind::Totp => "totp/",
        Kind::Hotp => "hotp/",
    }
}

/// Base32 (RFC 4648, upper, padded) as WinAuth emits it.
pub fn encode_secret_base32(secret: &[u8]) -> String {
    data_encoding::BASE32.encode(secret)
}

/// Decode a base32 secret, tolerating lowercase, spaces and missing padding.
pub fn decode_secret_base32(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .trim()
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '-')
        .collect();
    let up = cleaned.to_ascii_uppercase();
    let padded = match up.len() % 8 {
        0 => up.clone(),
        r => format!("{}{}", up, "=".repeat(8 - r)),
    };
    data_encoding::BASE32
        .decode(padded.as_bytes())
        .map_err(|e| format!("invalid base32 secret: {e}"))
}

/// Decode an otpauth URI (or a bare otpauth line). Returns parsed account.
///
/// Tolerances: missing scheme separator variants, `+` as space in labels,
/// unpadded base32, unknown parameters preserved in `extra`.
pub fn parse_otpauth(line: &str) -> Result<Account, String> {
    let line = line.trim();
    let rest = line
        .strip_prefix("otpauth://")
        .ok_or_else(|| "not an otpauth:// URI".to_string())?;
    let (head, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (kind_str, label_raw) = head.split_once('/').unwrap_or((head, ""));
    let kind = match kind_str.to_ascii_lowercase().as_str() {
        "totp" => Kind::Totp,
        "hotp" => Kind::Hotp,
        other => return Err(format!("unknown authenticator type {other:?}")),
    };

    let mut params: BTreeMap<String, String> = BTreeMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        params.insert(k.to_ascii_lowercase(), percent_decode_plus(v));
    }

    let secret_b32 = params
        .remove("secret")
        .ok_or_else(|| "missing secret parameter".to_string())?;
    let secret = decode_secret_base32(&secret_b32)?;

    let mut label = percent_decode_plus(label_raw);
    label = label.replace('+', " "); // WinAuth: space was encoded as '+'

    // issuer: explicit param wins; else "Issuer: label" / "Issuer - label" heuristic
    let mut issuer = String::new();
    if let Some(i) = params.remove("issuer").filter(|i| !i.is_empty()) {
        issuer = i.replace('+', " ");
        // de-duplicate "issuer: label" style labels
        for pref in [format!("{issuer}: "), format!("{issuer}:"), format!("{issuer} - "), format!("{issuer}-")] {
            if let Some(stripped) = label.strip_prefix(pref.as_str()) {
                label = stripped.to_string();
                break;
            }
        }
    } else if let Some((i, l)) = label.split_once([':', '-']).map(|(a, b)| (a.trim(), b.trim())) {
        if !i.is_empty() && !l.is_empty() && a_looks_like_issuer(i) {
            issuer = i.to_string();
            label = l.to_string();
        }
    }

    let digits = params
        .remove("digits")
        .and_then(|d| d.parse::<u32>().ok())
        .filter(|d| (6..=10).contains(d))
        .unwrap_or(6);
    let algorithm = params
        .remove("algorithm")
        .and_then(|a| Algorithm::parse(&a))
        .unwrap_or(Algorithm::Sha1);
    let period = params
        .remove("period")
        .and_then(|p| p.parse::<u64>().ok())
        .filter(|p| *p > 0)
        .unwrap_or(30);
    let counter = match kind {
        Kind::Hotp => params
            .remove("counter")
            .and_then(|c| c.parse::<u64>().ok())
            .unwrap_or(0),
        Kind::Totp => 0,
    };

    Ok(Account {
        kind,
        issuer,
        label,
        secret,
        digits,
        algorithm,
        period,
        counter,
        extra: params,
    })
}

fn a_looks_like_issuer(s: &str) -> bool {
    !s.contains('@') && s.chars().next().is_some_and(|c| c.is_alphabetic())
}

/// percent-decode that does NOT translate '+' (we handle it ourselves).
fn percent_decode_plus(s: &str) -> String {
    // urlencoding::decode leaves '+' intact already.
    urlencoding::decode(s).unwrap_or_else(|_| s.into()).into_owned()
}

/// Parse a whole WinAuth export text (one URI per line). Blank lines and
/// lines that are not otpauth URIs produce errors collected alongside the
/// successes so a bad line never aborts a whole import.
pub fn parse_export(text: &str) -> (Vec<Account>, Vec<(usize, String)>) {
    let mut accounts = Vec::new();
    let mut errors = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match parse_otpauth(line) {
            Ok(a) => accounts.push(a),
            Err(e) => errors.push((i + 1, e)),
        }
    }
    (accounts, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_winauth_style_line() {
        let line = "otpauth://totp/signin.lumen.com:sysadmin%40example.com?secret=JBSWY3DPEHPK3PXP&digits=6&issuer=signin.lumen.com";
        let a = parse_otpauth(line).unwrap();
        assert_eq!(a.kind, Kind::Totp);
        assert_eq!(a.issuer, "signin.lumen.com");
        assert_eq!(a.label, "sysadmin@example.com");
        assert_eq!(a.secret.len(), 10);
        assert_eq!(&a.secret[..5], b"Hello");
    }

    #[test]
    fn unpadded_base32_ok() {
        let line = "otpauth://totp/Test?secret=JBSWY3DP&digits=6";
        let a = parse_otpauth(line).unwrap();
        assert_eq!(a.secret, b"Hello");
    }

    #[test]
    fn plus_in_label_is_space() {
        let line = "otpauth://totp/DarkTrace+Customer+Portal?secret=JBSWY3DPEHPK3PXP";
        let a = parse_otpauth(line).unwrap();
        assert_eq!(a.label, "DarkTrace Customer Portal");
    }

    #[test]
    fn extras_preserved() {
        let line = "otpauth://totp/Steam?secret=JBSWY3DP&deviceid=abc123&data=xyz";
        let a = parse_otpauth(line).unwrap();
        assert_eq!(a.extra.get("deviceid").map(String::as_str), Some("abc123"));
        assert_eq!(a.extra.get("data").map(String::as_str), Some("xyz"));
    }

    #[test]
    fn roundtrip_uri() {
        let line = "otpauth://totp/Acme%3Auser%40acme.com?secret=JBSWY3DPEHPK3PXP&digits=6&issuer=Acme&algorithm=SHA256&period=60";
        let a = parse_otpauth(line).unwrap();
        let b = parse_otpauth(&a.to_uri()).unwrap();
        assert_eq!(a.issuer, b.issuer);
        assert_eq!(a.secret, b.secret);
        assert_eq!(a.algorithm, b.algorithm);
        assert_eq!(a.period, b.period);
    }
}
