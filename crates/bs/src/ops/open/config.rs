// SPDX-License-Identifier: FSL-1.1

use provenance_log::{key::key_paths::ValidatedKeyParams, Script};

use crate::{
    params::vlad::{FirstEntryKeyParams, VladParams},
    update::op_params::OpParams,
};

/// the configuration for opening a new provenance log
#[derive(bon::Builder, Clone, Debug)]
pub struct Config<T: ValidatedKeyParams = FirstEntryKeyParams> {
    /// the vlad key and cid params
    pub vlad: (OpParams, OpParams),

    /// the entry key params
    pub entrykey: OpParams,

    /// the pubkey params
    pub pubkey: OpParams,

    /// The first lock script
    pub first_lock: Script,

    /// entry lock script
    pub lock: Script,

    /// entry unlock script
    pub unlock: Script,

    /// additional ops for the first entry
    #[builder(default = Vec::new())]
    pub additional_ops: Vec<OpParams>,

    /// Phantom data to remember the FirstEntryKey parameter type
    #[builder(skip)]
    pub _phantom: std::marker::PhantomData<T>,
}

impl<T: ValidatedKeyParams> Config<T> {
    /// Set up the config with VladParams of the same type parameter
    pub fn with_typed_vlad_params(mut self, params: VladParams<T>) -> Self {
        self.vlad = params.into();
        self
    }

    /// Set up the first lock script automatically from VladParams
    pub fn with_default_first_lock_script(mut self) -> Self {
        self.first_lock = Script::Code(
            provenance_log::Key::default(),
            VladParams::<T>::first_lock_script(),
        );
        self
    }

    /// Add additional operations
    pub fn add_ops(mut self, ops: Vec<OpParams>) -> Self {
        self.additional_ops.extend(ops);
        self
    }

    /// Add a single additional operation
    pub fn add_op(mut self, op: OpParams) -> Self {
        self.additional_ops.push(op);
        self
    }
}

impl<T: ValidatedKeyParams> From<Config<T>> for Vec<OpParams> {
    fn from(config: Config<T>) -> Self {
        let mut ops = vec![config.vlad.0, config.vlad.1, config.entrykey, config.pubkey];
        ops.extend(config.additional_ops);
        ops
    }
}
