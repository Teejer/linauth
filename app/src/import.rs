//! Import WinAuth backups: password-protected .zip (ZipCrypto, as WinAuth
//! writes) or plain .txt with one otpauth URI per line.

use std::io::Read;
use std::path::Path;

use crate::uri::{self, Account};

pub struct ImportResult {
    pub accounts: Vec<Account>,
    pub errors: Vec<(usize, String)>,
}

pub fn import_file(path: &Path, password: Option<&str>) -> Result<ImportResult, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let text = if is_zip(&bytes) {
        read_zip(bytes, password)?
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let (accounts, errors) = uri::parse_export(&text);
    if accounts.is_empty() && errors.is_empty() {
        return Err("no otpauth entries found".into());
    }
    Ok(ImportResult { accounts, errors })
}

fn is_zip(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06")
}

fn read_zip(bytes: Vec<u8>, password: Option<&str>) -> Result<String, String> {
    let reader = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| format!("bad zip: {e}"))?;
    let mut out = String::new();
    for i in 0..archive.len() {
        let mut buf = Vec::new();
        let mut entry = match password {
            Some(p) => archive
                .by_index_decrypt(i, p.as_bytes())
                .map_err(|e| format!("wrong password or corrupt zip: {e}"))?,
            None => archive.by_index(i).map_err(|e| {
                format!("entry looks encrypted or unreadable ({e}); provide the zip password")
            })?,
        };
        entry
            .read_to_end(&mut buf)
            .map_err(|e| format!("failed reading zip entry: {e}"))?;
        out.push_str(&String::from_utf8_lossy(&buf));
    }
    Ok(out)
}
