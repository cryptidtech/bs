// SPDX-License-Identifier: FSL-1.1

use provenance_log::Script;

use crate::update::op_params::OpParams;

/// the configuration for opening a new provenance log
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// the vlad key and cid params
    pub vlad_params: (OpParams, OpParams),

    /// the entry key params
    pub entrykey_params: OpParams,

    /// the pubkey params
    pub pubkey_params: OpParams,

    /// The first lock script
    pub first_lock_script: Script,

    /// entry lock script
    pub entry_lock_script: Script,

    /// entry unlock script
    pub entry_unlock_script: Script,

    /// additional ops for the first entry
    pub additional_ops: Vec<OpParams>,
}

impl Config {
    /// add the vlad key and cid params
    pub fn with_vlad_params(mut self, key: OpParams, cid: OpParams) -> Self {
        self.vlad_params = (key, cid);
        self
    }

    /// add the entrykey params
    pub fn with_entrykey_params(mut self, key: OpParams) -> Self {
        self.entrykey_params = key;
        self
    }

    /// add the pubkey params
    pub fn with_pubkey_params(mut self, key: OpParams) -> Self {
        self.pubkey_params = key;
        self
    }

    /// Set the entry lock Script
    pub fn with_entry_lock_script(&mut self, script: Script) -> &mut Self {
        self.entry_lock_script = script;
        self
    }

    /// Set the entry unlock script
    pub fn with_entry_unlock_script(&mut self, script: Script) -> &mut Self {
        self.entry_unlock_script = script;
        self
    }

    /// add additional ops
    pub fn with_additional_ops(mut self, ops: &[OpParams]) -> Self {
        self.additional_ops.append(&mut ops.to_vec());
        self
    }
}
