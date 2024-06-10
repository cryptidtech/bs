// SPDX-License-Identifier: FSL-1.1
use provenance_log::Op;
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

    /// entry operations
    pub entry_ops: Vec<Op>,
}

impl Config {
    /// are we clearing lock scripts?
    pub fn clear_lock_scripts(mut self, clear: bool) -> Self {
        self.clear_lock_scripts = clear;
        self
    }

    /// lock scripts we're adding
    pub fn add_lock_script<S: AsRef<str>, P: AsRef<Path>>(mut self, key_path: &S, path: &P) -> Self {
        self.add_entry_lock_scripts.push((key_path.as_ref().to_string(), path.as_ref().to_path_buf()));
        self
    }

    /// lock scripts we're removing
    pub fn remove_lock_script<S: AsRef<str>>(mut self, key_path: &S) -> Self {
        self.remove_entry_lock_scripts.push(key_path.as_ref().to_string());
        self
    }

    /// the ops we're recording
    pub fn with_op(mut self, op: &Op) -> Self {
        self.entry_ops.push(op.clone());
        self
    }
}
