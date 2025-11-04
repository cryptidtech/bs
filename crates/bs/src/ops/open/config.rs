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
    vlad: VladParams<T>,

    /// the entry key params
    entrykey: OpParams,

    /// the pubkey params
    pubkey: OpParams,

    /// The first lock script
    #[builder(skip = Self::default_first_lock())]
    first_lock: Script,

    /// entry lock script
    lock: Script,

    /// entry unlock script
    unlock: Script,

    /// additional ops for the first entry
    #[builder(default = Vec::new())]
    additional_ops: Vec<OpParams>,
}

impl<T: ValidatedKeyParams> Config<T> {
    /// Get the vlad params
    pub fn vlad_params(&self) -> &VladParams<T> {
        &self.vlad
    }

    /// Get the first lock script
    pub fn first_lock(&self) -> &Script {
        &self.first_lock
    }

    /// Get the entry key params
    pub fn entrykey(&self) -> &OpParams {
        &self.entrykey
    }

    /// Get the pubkey params
    pub fn pubkey(&self) -> &OpParams {
        &self.pubkey
    }

    /// Get the entry lock script
    pub fn lock_script(&self) -> &Script {
        &self.lock
    }

    /// Get the entry unlock script
    pub fn unlock(&self) -> &Script {
        &self.unlock
    }

    /// Get the additional operations
    pub fn additional_ops(&self) -> &[OpParams] {
        &self.additional_ops
    }
}

impl<T: ValidatedKeyParams, S: config_builder::State> ConfigBuilder<T, S> {
    // Default function for first_lock
    fn default_first_lock() -> Script {
        Script::Code(
            provenance_log::Key::default(),
            VladParams::<T>::first_lock_script(),
        )
    }
}

impl<T: ValidatedKeyParams> From<Config<T>> for Vec<OpParams> {
    fn from(config: Config<T>) -> Self {
        // Gather all the operations from this config so we can store their values against their Cids
        let (vlad_key_op, vlad_cid_op): (OpParams, OpParams) = config.vlad.into();

        let mut ops = vec![vlad_key_op, vlad_cid_op, config.entrykey, config.pubkey];
        ops.extend(config.additional_ops);
        ops
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::params::anykey::RecoveryKeyParams;
    use crate::params::vlad::FirstEntryKeyParams;
    use multicodec::Codec;
    use provenance_log::{Key, Script};

    #[test]
    fn test_config_default_first_lock() {
        // Create a Config with default type parameter (FirstEntryKeyParams)
        let config = Config::builder()
            .vlad(Default::default())
            .entrykey(Default::default())
            .pubkey(Default::default())
            .lock(Script::Code(Key::default(), "test lock".to_string()))
            .unlock(Script::Code(Key::default(), "test unlock".to_string()))
            .build();

        // The first_lock should be automatically set with FirstEntryKeyParams
        let expected_script = Script::Code(
            Key::default(),
            VladParams::<FirstEntryKeyParams>::first_lock_script(),
        );
        assert_eq!(config.first_lock, expected_script);
    }

    // Not recommended, but test it anyway: use non-standard vlad key
    #[test]
    fn test_config_with_recovery_key_params() {
        let config: Config<RecoveryKeyParams> = Config::<RecoveryKeyParams>::builder()
            .vlad(VladParams::<RecoveryKeyParams>::builder().build())
            .entrykey(Default::default())
            .pubkey(Default::default())
            .lock(Script::Code(Key::default(), "test lock".to_string()))
            .unlock(Script::Code(Key::default(), "test unlock".to_string()))
            .build();

        // The first_lock should be automatically set with RecoveryKeyParams
        let expected_script = Script::Code(
            Key::default(),
            VladParams::<RecoveryKeyParams>::first_lock_script(),
        );
        assert_eq!(config.first_lock, expected_script);
    }

    #[test]
    fn test_with_typed_vlad_params() {
        // Create VladParams with specific type
        let vlad_params = VladParams::<FirstEntryKeyParams>::builder()
            .key(Codec::Ed25519Priv)
            .build();

        // Create Config and set VladParams
        let config = Config::<FirstEntryKeyParams>::builder()
            .vlad(Default::default())
            .entrykey(Default::default())
            .pubkey(Default::default())
            .lock(Script::Code(Key::default(), "test lock".to_string()))
            .unlock(Script::Code(Key::default(), "test unlock".to_string()))
            .build();

        // Verify the vlad parameters were set correctly
        assert_eq!(config.vlad, vlad_params);
    }

    #[test]
    fn test_add_ops() {
        // Additional operations
        let ops = vec![
            OpParams::UseBin {
                key: "/test/path".try_into().unwrap(),
                data: vec![1, 2, 3],
            },
            OpParams::UseStr {
                key: "/test/string".try_into().unwrap(),
                s: "test string".to_string(),
            },
        ];

        // Create a Config
        let config = Config::builder()
            .vlad(Default::default())
            .entrykey(Default::default())
            .pubkey(Default::default())
            .lock(Script::Code(Key::default(), "test lock".to_string()))
            .unlock(Script::Code(Key::default(), "test unlock".to_string()))
            .additional_ops(ops.clone())
            .build();

        // Verify the operations were added
        assert_eq!(config.additional_ops, ops);
    }

    #[test]
    fn test_add_single_op() {
        // Add a single operation
        let op = OpParams::UseStr {
            key: "/test/single".try_into().unwrap(),
            s: "test string".to_string(),
        };

        // Create a Config
        let config = Config::builder()
            .vlad(Default::default())
            .entrykey(Default::default())
            .pubkey(Default::default())
            .lock(Script::Code(Key::default(), "test lock".to_string()))
            .unlock(Script::Code(Key::default(), "test unlock".to_string()))
            .additional_ops(vec![op.clone()])
            .build();

        // Verify the operation was added
        assert_eq!(config.additional_ops.len(), 1);
        assert_eq!(config.additional_ops[0], op);
    }

    // Test that would have caught the original bug - mixing type parameters
    #[test]
    fn test_type_consistency() {
        let vlad_params = VladParams::<FirstEntryKeyParams>::default();

        // This would be a compile error if we tried to use the wrong type
        let config = Config::<FirstEntryKeyParams>::builder()
            .vlad(vlad_params)
            .entrykey(Default::default())
            .pubkey(Default::default())
            .lock(Script::Code(Key::default(), "test lock".to_string()))
            .unlock(Script::Code(Key::default(), "test unlock".to_string()))
            .build();

        // Verify first_lock has correct script
        let expected_script = Script::Code(
            Key::default(),
            VladParams::<FirstEntryKeyParams>::first_lock_script(),
        );
        assert_eq!(config.first_lock, expected_script);

        // The following would be a compile error if written:
        // let wrong_vlad = VladParams::<RecoveryKeyParams>::default();
        // config.with_typed_vlad_params(wrong_vlad); // Type mismatch error
    }
}
