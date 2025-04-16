// SPDX-License-Identifier: FSL-1.1
use crate::update::op_params::OpParams;
use multikey::Multikey;
use std::path::{Path, PathBuf};

/// the configuration for opening a new provenance log
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// clear all lock scripts?
    pub clear_lock_scripts: bool,

    /// entry lock script
    pub add_entry_lock_scripts: Vec<(String, PathBuf)>,

    /// remove lock scripts
    pub remove_entry_lock_scripts: Vec<String>,

    /// entry unlock script
    pub entry_unlock_script: Option<PathBuf>,

    /// entry signing key
    pub entry_signing_key: Option<Multikey>,

    /// entry operations
    pub entry_ops: Vec<OpParams>,
}

impl Config {
    /// are we clearing lock scripts?
    pub fn clear_lock_scripts(mut self, clear: bool) -> Self {
        self.clear_lock_scripts = clear;
        self
    }

    /// lock scripts we're adding
    pub fn add_lock_script<S: AsRef<str>, P: AsRef<Path>>(
        mut self,
        key_path: &S,
        path: &P,
    ) -> Self {
        self.add_entry_lock_scripts
            .push((key_path.as_ref().to_string(), path.as_ref().to_path_buf()));
        self
    }

    /// add in the entry unlock script
    pub fn with_entry_unlock_script<P: AsRef<Path>>(mut self, path: &P) -> Self {
        self.entry_unlock_script = Some(path.as_ref().to_path_buf());
        self
    }

    /// add in the entry signing key
    pub fn with_entry_signing_key(mut self, mk: &Multikey) -> Self {
        self.entry_signing_key = Some(mk.clone());
        self
    }

    /// lock scripts we're removing
    pub fn remove_lock_script<S: AsRef<str>>(mut self, key_path: &S) -> Self {
        self.remove_entry_lock_scripts
            .push(key_path.as_ref().to_string());
        self
    }

    /// the ops we're recording
    pub fn with_ops(mut self, ops: &[OpParams]) -> Self {
        self.entry_ops.append(&mut ops.to_vec());
        self
    }
}
