//! App preferences persisted to $XDG_CONFIG_HOME/linauth/config.json.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

pub fn config_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")
        })
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// copy the code with a single click instead of double-click/Enter
    pub copy_on_single_click: bool,
}

impl Config {
    fn path() -> PathBuf {
        config_dir().join("linauth").join("config.json")
    }

    pub fn load() -> Config {
        fs::read(Self::path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let p = Self::path();
        if let Some(dir) = p.parent() {
            fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        fs::write(&p, json).map_err(|e| e.to_string())
    }
}
