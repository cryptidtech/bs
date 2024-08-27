// SPDX-License-Identifier: FSL-1.1

use crate::update::op_params::OpParams;
use std::path::{Path, PathBuf};

/// the configuration for opening a new provenance log
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// the vlad key and cid params
    pub vlad_params: Option<(OpParams, OpParams)>,

    /// the entry key params
    pub entrykey_params: Option<OpParams>,

    /// the pubkey params
    pub pubkey_params: Option<OpParams>,

    /// entry lock script
    pub entry_lock_script: Option<PathBuf>,

    /// entry unlock script
    pub entry_unlock_script: Option<PathBuf>,

    /// additional ops for the first entry
    pub additional_ops: Vec<OpParams>,
}

impl Config {
    /// add the vlad key and cid params
    pub fn with_vlad_params(mut self, key: OpParams, cid: OpParams) -> Self {
        self.vlad_params = Some((key, cid));
        self
    }

    /// add the entrykey params
    pub fn with_entrykey_params(mut self, key: OpParams) -> Self {
        self.entrykey_params = Some(key);
        self
    }

    /// add the pubkey params
    pub fn with_pubkey_params(mut self, key: OpParams) -> Self {
        self.pubkey_params = Some(key);
        self
    }

    /// add the entry lock script
    pub fn with_entry_lock_script<P: AsRef<Path>>(mut self, path: &P) -> Self {
        self.entry_lock_script = Some(path.as_ref().to_path_buf());
        self
    }

    /// add in the entry unlock script
    pub fn with_entry_unlock_script<P: AsRef<Path>>(mut self, path: &P) -> Self {
        self.entry_unlock_script = Some(path.as_ref().to_path_buf());
        self
    }

    /// add additional ops
    pub fn with_additional_ops(mut self, ops: &[OpParams]) -> Self {
        self.additional_ops.append(&mut ops.to_vec());
        self
    }
}
