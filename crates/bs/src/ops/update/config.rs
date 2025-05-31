// SPDX-License-Identifier: FSL-1.1
use crate::update::op_params::OpParams;
use provenance_log::{Key, Script};

/// the configuration for opening a new provenance log
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// clear all lock scripts?
    pub clear_lock_scripts: bool,

    /// entry lock script
    pub add_entry_lock_scripts: Vec<(String, Script)>,

    /// remove lock scripts
    pub remove_entry_lock_scripts: Vec<String>,

    /// entry unlock script
    pub entry_unlock_script: Script,

    /// entry signing key
    pub entry_signing_key: Key,

    /// entry operations
    pub entry_ops: Vec<OpParams>,
}

impl Config {
    /// Create a new Config with the given unlock script and entry signing key
    pub fn new(entry_unlock_script: Script, entry_signing_key: Key) -> Self {
        Self {
            clear_lock_scripts: false,
            add_entry_lock_scripts: Vec::new(),
            remove_entry_lock_scripts: Vec::new(),
            entry_unlock_script,
            entry_signing_key,
            entry_ops: Vec::new(),
        }
    }
    /// are we clearing lock scripts?
    pub fn clear_lock_scripts(mut self, clear: bool) -> Self {
        self.clear_lock_scripts = clear;
        self
    }

    /// lock scripts we're adding
    pub fn add_lock_script(&mut self, key_path: impl AsRef<str>, script: Script) -> &mut Self {
        self.add_entry_lock_scripts
            .push((key_path.as_ref().to_string(), script));
        self
    }

    /// lock scripts we're removing
    pub fn remove_lock_script<S: AsRef<str>>(mut self, key_path: &S) -> Self {
        self.remove_entry_lock_scripts
            .push(key_path.as_ref().to_string());
        self
    }

    /// the ops we're recording
    pub fn with_ops(&mut self, ops: &[OpParams]) -> &mut Self {
        self.entry_ops.append(&mut ops.to_vec());
        self
    }

    /// Build the configuration
    pub fn build(&self) -> Self {
        self.clone()
    }
}

impl From<Config> for Vec<OpParams> {
    fn from(config: Config) -> Self {
        config.entry_ops
    }
}
