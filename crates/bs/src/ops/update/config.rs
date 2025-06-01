// SPDX-License-Identifier: FSL-1.1
use crate::update::op_params::OpParams;
use provenance_log::{Key, Script};

/// The configuration for updating a provenance log
#[derive(bon::Builder, Clone, Debug)]
pub struct Config {
    /// Entry unlock script used for the new entry
    pub entry_unlock_script: Script,

    /// Key path for the signing key
    pub entry_signing_key: Key,

    /// Whether to clear all existing lock scripts
    #[builder(default = false)]
    pub clear_lock_scripts: bool,

    /// Lock scripts to add (key_path, script)
    #[builder(default = Vec::new())]
    pub add_entry_lock_scripts: Vec<(Key, Script)>,

    /// Key paths of lock scripts to remove
    #[builder(default = Vec::new())]
    pub remove_entry_lock_scripts: Vec<Key>,

    /// Operations to perform in this entry
    #[builder(default = Vec::new())]
    pub entry_ops: Vec<OpParams>,
}

impl Config {
    /// Create a new Config with the given unlock script and entry signing key
    /// (Kept for backwards compatibility)
    pub fn new(entry_unlock_script: Script, entry_signing_key: Key) -> Self {
        let mut config = Config::builder()
            .entry_unlock_script(entry_unlock_script)
            .entry_signing_key(entry_signing_key)
            .build();

        // Initialize default values that the old API expected
        config.clear_lock_scripts = false;
        config.add_entry_lock_scripts = Vec::new();
        config.remove_entry_lock_scripts = Vec::new();
        config.entry_ops = Vec::new();

        config
    }

    /// Add a lock script at the specified key path
    pub fn add_lock_script(mut self, key_path: Key, script: Script) -> Self {
        self.add_entry_lock_scripts.push((key_path, script));
        self
    }

    /// Remove a lock script at the specified key path
    pub fn remove_lock_script(mut self, key_path: Key) -> Self {
        self.remove_entry_lock_scripts.push(key_path);
        self
    }

    /// Add multiple operations
    pub fn add_ops(mut self, ops: Vec<OpParams>) -> Self {
        self.entry_ops.extend(ops);
        self
    }

    /// Add a single operation
    pub fn add_op(mut self, op: OpParams) -> Self {
        self.entry_ops.push(op);
        self
    }

    /// For backwards compatibility with the current API
    pub fn with_ops(&mut self, ops: &[OpParams]) -> &mut Self {
        self.entry_ops.extend(ops.to_vec());
        self
    }

    /// For backwards compatibility with the current API
    pub fn build(&self) -> Self {
        self.clone()
    }
}

impl From<Config> for Vec<OpParams> {
    fn from(config: Config) -> Self {
        config.entry_ops.clone()
    }
}
