// SPDX-License-Identifier: FSL-1.1
use crate::update::op_params::OpParams;
use provenance_log::{Key, Script};

/// The configuration for updating a provenance log
#[derive(bon::Builder, Clone, Debug)]
pub struct Config {
    /// [provenance_log::Entry] unlock [provenance_log::Script] used for the new entry
    unlock: Script,

    /// [Key] path for the signing key for this [provenance_log::Entry]
    entry_signing_key: Key,

    /// Whether to clear all existing lock scripts
    #[builder(default = false)]
    clear_lock_scripts: bool,

    /// Lock [provenance_log::Script] to add
    #[builder(default = Vec::new())]
    add_entry_lock_scripts: Vec<(Key, Script)>,

    /// Key paths of lock scripts to remove
    #[builder(default = Vec::new())]
    remove_entry_lock_scripts: Vec<Key>,

    /// Operations to perform in this entry
    #[builder(default = Vec::new())]
    additional_ops: Vec<OpParams>,
}

impl Config {
    /// Returns the additional ops
    pub fn additional_ops(&self) -> &[OpParams] {
        &self.additional_ops
    }

    /// Returns unlock script
    pub fn unlock(&self) -> &Script {
        &self.unlock
    }

    /// Returns the entry signing key
    pub fn entry_signing_key(&self) -> &Key {
        &self.entry_signing_key
    }
}

impl From<Config> for Vec<OpParams> {
    fn from(config: Config) -> Self {
        config.additional_ops.clone()
    }
}
