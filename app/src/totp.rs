//! RFC 4226 (HOTP) / RFC 6238 (TOTP) generation.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" => Some(Self::Sha1),
            "SHA256" => Some(Self::Sha256),
            "SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// Truncated dynamic code (RFC 4226 section 5.3) for a counter value.
pub fn hotp(secret: &[u8], counter: u64, digits: u32, algo: Algorithm) -> String {
    let code = match algo {
        Algorithm::Sha1 => {
            let mut m = Hmac::<Sha1>::new_from_slice(secret).expect("hmac-sha1 accepts any key");
            m.update(&counter.to_be_bytes());
            m.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut m =
                Hmac::<Sha256>::new_from_slice(secret).expect("hmac-sha256 accepts any key");
            m.update(&counter.to_be_bytes());
            m.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut m =
                Hmac::<Sha512>::new_from_slice(secret).expect("hmac-sha512 accepts any key");
            m.update(&counter.to_be_bytes());
            m.finalize().into_bytes().to_vec()
        }
    };
    let offset = (code.last().unwrap_or(&0) & 0x0f) as usize;
    let bin = ((code[offset] & 0x7f) as u32) << 24
        | (code[offset + 1] as u32) << 16
        | (code[offset + 2] as u32) << 8
        | code[offset + 3] as u32;
    let modulus = 10u32.pow(digits.min(9));
    format!("{:0digits$}", bin % modulus, digits = digits.min(9) as usize)
}

/// Current TOTP for `unix_time` with the given period.
pub fn totp(secret: &[u8], unix_time: u64, period: u64, digits: u32, algo: Algorithm) -> String {
    hotp(secret, unix_time / period, digits, algo)
}

/// Seconds remaining before the current TOTP window rolls over.
pub fn seconds_remaining(unix_time: u64, period: u64) -> u64 {
    period - (unix_time % period)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Vec<u8> {
        b"12345678901234567890".to_vec()
    }

    #[test]
    fn rfc4226_vectors() {
        for (i, expect) in ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"].iter().enumerate() {
            assert_eq!(hotp(&secret(), i as u64, 6, Algorithm::Sha1), *expect);
        }
    }

    #[test]
    fn rfc6238_vectors_sha1() {
        // RFC 6238 Appendix B, T values mod 30 windows (8 digits)
        let cases: [(u64, &str); 7] = [
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
            (200000000000, "65649215"),
        ];
        for (t, expect) in cases {
            assert_eq!(totp(&secret(), t, 30, 8, Algorithm::Sha1), expect, "t={t}");
        }
    }

    #[test]
    fn rfc6238_vectors_sha256() {
        let s = b"12345678901234567890123456789012".to_vec();
        assert_eq!(totp(&s, 59, 30, 8, Algorithm::Sha256), "46119246");
        assert_eq!(totp(&s, 1111111109, 30, 8, Algorithm::Sha256), "68084774");
    }

    #[test]
    fn rfc6238_vectors_sha512() {
        let mut s = b"12345678901234567890123456789012345678901234567890123456789012345678901234567890".to_vec();
        s.truncate(64);
        assert_eq!(totp(&s, 59, 30, 8, Algorithm::Sha512), "90693936");
    }
}
