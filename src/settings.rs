// Loads and saves application settings.
use crate::case::{Result, atomic_json};
use serde::{Deserialize, Serialize};
use std::{fs, num::NonZeroUsize, path::PathBuf};

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub executable: PathBuf,
    pub symbols: PathBuf,
    pub offline: bool,
    pub max_concurrent_jobs: NonZeroUsize,
    pub recent_cases: Vec<PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            executable: PathBuf::new(),
            symbols: PathBuf::new(),
            offline: false,
            max_concurrent_jobs: NonZeroUsize::new(2).unwrap(),
            recent_cases: Vec::new(),
        }
    }
}

impl Settings {
    pub fn path() -> PathBuf {
        std::env::var_os("VOLGUI_CONFIG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var_os("APPDATA")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("VolGUI")
            })
            .join("settings.json")
    }

    pub fn load() -> Result<Self> {
        let path = Self::path();
        let mut settings = if path.exists() {
            serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("Cannot read settings: {e}"))?
        } else {
            Self::default()
        };
        if let Some(path) = std::env::var_os("VOLGUI_VOLATILITY") {
            settings.executable = PathBuf::from(path);
        }
        Ok(settings)
    }

    pub fn save(&self) -> Result<()> {
        atomic_json(&Self::path(), self)
    }

    pub fn remember(&mut self, path: PathBuf) -> Result<()> {
        self.recent_cases.retain(|p| p != &path);
        self.recent_cases.insert(0, path);
        self.recent_cases.truncate(8);
        self.save()
    }
}
