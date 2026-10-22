//! Local account store: JSON, optionally encrypted at rest with a master
//! password (Argon2id -> XChaCha20-Poly1305). File:
//! ~/.local/share/linauth/accounts.json[.enc]

use std::fs;
use std::path::PathBuf;

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::uri::Account;

const MAGIC: &[u8; 8] = b"WNGTKENC"; // winauth-gtk enc v1
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

#[derive(Serialize, Deserialize, Default)]
pub struct Store {
    #[serde(default)]
    pub accounts: Vec<SavedAccount>,
}

#[derive(Serialize, Deserialize)]
pub struct SavedAccount {
    #[serde(flatten)]
    pub account: Account,
    /// sort order / manual pin
    #[serde(default)]
    pub pinned: bool,
}

pub struct StorePath(PathBuf);

impl StorePath {
    pub fn new() -> Self {
        let dir = dirs_next().join("linauth");
        if !dir.exists() {
            // migrate from the pre-rename winauth-gtk location
            let old = dirs_next().join("winauth-gtk");
            if old.exists() {
                let _ = fs::rename(&old, &dir);
            }
        }
        let _ = fs::create_dir_all(&dir);
        StorePath(dir)
    }
    fn plain(&self) -> PathBuf {
        self.0.join("accounts.json")
    }
    fn encrypted(&self) -> PathBuf {
        self.0.join("accounts.json.enc")
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted().exists()
    }

    pub fn load(&self, password: Option<&str>) -> Result<Store, String> {
        if self.encrypted().exists() {
            let pw = password.ok_or("store is encrypted; password required")?;
            let blob = fs::read(self.encrypted()).map_err(|e| e.to_string())?;
            let json = decrypt(&blob, pw)?;
            serde_json::from_slice(&json).map_err(|e| format!("corrupt store: {e}"))
        } else if self.plain().exists() {
            let data = fs::read(self.plain()).map_err(|e| e.to_string())?;
            serde_json::from_slice(&data).map_err(|e| format!("corrupt store: {e}"))
        } else {
            Ok(Store::default())
        }
    }

    pub fn save(&self, store: &Store, password: Option<&str>) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(store).map_err(|e| e.to_string())?;
        match password {
            Some(pw) => {
                let blob = encrypt(&json, pw)?;
                fs::write(self.encrypted(), blob).map_err(|e| e.to_string())?;
                // if migrating plain -> encrypted, remove plaintext copy
                let _ = fs::remove_file(self.plain());
            }
            None => {
                let mut perm = std::fs::Permissions::from_mode(0o600);
                let _ = &mut perm;
                fs::write(self.plain(), &json).map_err(|e| e.to_string())?;
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(self.plain(), fs::Permissions::from_mode(0o600));
            }
        }
        Ok(())
    }
}

fn kdf(password: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .expect("32-byte output is supported");
    key
}

fn encrypt(plain: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|e| e.to_string())?;
    getrandom::fill(&mut nonce_bytes).map_err(|e| e.to_string())?;
    let key = kdf(password, &salt);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), plain)
        .map_err(|_| "encryption failed".to_string())?;
    let mut blob = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ct.len());
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

fn decrypt(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let rest = blob
        .strip_prefix(MAGIC)
        .ok_or("not a linauth encrypted store")?;
    if rest.len() < SALT_LEN + NONCE_LEN + 16 {
        return Err("truncated store".into());
    }
    let (salt, rest) = rest.split_at(SALT_LEN);
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    let key = kdf(password, salt);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| "wrong password".to_string())
}

fn dirs_next() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").unwrap_or_default();
            PathBuf::from(home).join(".local/share")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enc_roundtrip_and_wrong_pw() {
        let data = b"{\"accounts\":[]}".to_vec();
        let blob = encrypt(&data, "hunter2").unwrap();
        assert_eq!(decrypt(&blob, "hunter2").unwrap(), data);
        assert!(decrypt(&blob, "wrong").is_err());
    }
}
