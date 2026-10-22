//! Export/backup in the exact format WinAuth produces, so a LinAuth backup
//! restores in WinAuth and vice versa.
//!
//! WinAuth's `WinAuthHelper.ExportAuthenticators` writes (for .zip targets) a
//! SharpZipLib archive encrypted with ZipCrypto, containing a single `.txt`
//! entry named after the zip file stem, holding one `otpauth://` URI per line
//! (CRLF line endings via .NET StreamWriter). We mirror that byte for byte in
//! spirit; `zip` writes the same ZipCrypto scheme.

use std::io::Write;
use std::path::Path;

use zip::unstable::write::FileOptionsExt;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::uri::{self, Account};

/// One otpauth URI per line, CRLF like WinAuth's StreamWriter.
pub fn to_export_text(accounts: &[Account]) -> String {
    let mut out = String::new();
    for a in accounts {
        out.push_str(&a.to_uri());
        out.push_str("\r\n");
    }
    out
}

/// Plain-text export (also importable by both LinAuth and WinAuth).
pub fn write_txt(path: &Path, accounts: &[Account]) -> Result<(), String> {
    let text = to_export_text(accounts);
    std::fs::write(path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// WinAuth-compatible backup zip. `password: Some` produces the traditional
/// ZipCrypto encryption WinAuth uses; `None` writes a plain (unencrypted) zip.
pub fn write_zip(path: &Path, accounts: &[Account], password: Option<&str>) -> Result<(), String> {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "backup path has no file name".to_string())?;
    let text = to_export_text(accounts);

    let file = std::fs::File::create(path).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    let mut zip = ZipWriter::new(file);
    let mut options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    if let Some(pw) = password {
        options = options.with_deprecated_encryption(pw.as_bytes());
    }
    // entry named after the zip stem: "LinAuth backup X.zip" -> "LinAuth backup X.txt"
    zip.start_file(format!("{stem}.txt"), options)
        .map_err(|e| format!("zip error: {e}"))?;
    zip.write_all(text.as_bytes())
        .map_err(|e| format!("zip write error: {e}"))?;
    zip.finish().map_err(|e| format!("zip finish error: {e}"))?;
    Ok(())
}

/// "LinAuth backup 2026-10-22.zip" — same "<name> <date>" shape as WinAuth's
/// "Winauth Master <date>".
pub fn default_backup_name(today: &str) -> String {
    format!("LinAuth backup {today}.zip")
}

/// "YYYY-MM-DD" from a unix timestamp (Hinnant's days->civil algorithm).
pub fn civil_date(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe as i64 + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn sample_accounts() -> Vec<Account> {
        let a = uri::parse_otpauth(
            "otpauth://totp/Acme%3Auser%40acme.com?secret=JBSWY3DPEHPK3PXP&digits=6&issuer=Acme&algorithm=SHA256&period=60",
        )
        .unwrap();
        let b = uri::parse_otpauth("otpauth://hotp/Badge?secret=JBSWY3DPEHPK3PXA&digits=8&counter=42")
            .unwrap();
        vec![a, b]
    }

    #[test]
    fn export_text_roundtrips_through_parser() {
        let accounts = sample_accounts();
        let text = to_export_text(&accounts);
        assert!(text.ends_with("\r\n"));
        let (parsed, errors) = uri::parse_export(&text);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].issuer, "Acme");
        assert_eq!(parsed[0].label, "user@acme.com");
        assert_eq!(parsed[0].secret, accounts[0].secret);
        assert_eq!(parsed[0].algorithm, accounts[0].algorithm);
        assert_eq!(parsed[0].period, 60);
        assert_eq!(parsed[1].counter, 42);
        assert_eq!(parsed[1].digits, 8);
    }

    #[test]
    fn zip_roundtrip_and_password_checks() {
        let accounts = sample_accounts();
        let dir = std::env::temp_dir().join(format!("linauth-export-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("LinAuth backup test.zip");

        write_zip(&path, &accounts, Some("hunter2")).unwrap();

        // inner entry must be named after the zip stem and be the .txt WinAuth expects
        {
            let f = std::fs::File::open(&path).unwrap();
            let names: Vec<String> = zip::ZipArchive::new(f)
                .unwrap()
                .file_names()
                .map(String::from)
                .collect();
            assert_eq!(names, vec!["LinAuth backup test.txt"]);
        }

        // our own importer reads it back with the password
        let res = crate::import::import_file(&path, Some("hunter2")).unwrap();
        assert_eq!(res.accounts.len(), 2);
        assert_eq!(res.accounts[0].label, "user@acme.com");

        // wrong password must fail, not return garbage
        assert!(crate::import::import_file(&path, Some("nope")).is_err());

        // unencrypted zip also works and stays importable
        let plain = dir.join("plain backup.zip");
        write_zip(&plain, &accounts, None).unwrap();
        let res = crate::import::import_file(&plain, None).unwrap();
        assert_eq!(res.accounts.len(), 2);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn civil_date_known_values() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(1_701_302_400), "2023-11-30");
        assert_eq!(civil_date(1_755_907_200), "2025-08-23");
    }
}
