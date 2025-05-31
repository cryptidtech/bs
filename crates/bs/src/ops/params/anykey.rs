//! Key Parameters Types for Operation Parameters.
//!
//! This module provides some concrete implementations of the generic way to define parameters for any key type based on
//! a path that identifies the key.
//!
//! # Creating Custom Key Types
//!
//! You can easily create your own key parameter types by using the [KeyParamsType] trait:
//!
//! ```rust
//! use provenance_log::key::util::{KeyParamsType, KeyParams};
//! use provenance_log::const_assert_valid_key;
//! use provenance_log::key::util::ValidatedKeyPath;
//! use bs::ops::update::OpParams;
//!
//! pub struct MyCustomKeyParams;
//!
//! impl KeyParamsType for MyCustomKeyParams {
//!     const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/my/special/key");
//! }
//!
//! // Create parameters with defaults
//! let params: OpParams = MyCustomKeyParams::default_params().into();
//!
//! // Or customize them
//! let custom = MyCustomKeyParams::params()
//!     .threshold(3)
//!     .build();
//! ```
//!
//! The blanket implementation to convert any type implementing `KeyParamsType` into a `Key`
//! can also be used on these concrete types.
//!
//! # Example
//!
//! ```rust
//! use provenance_log::Key;
//! use provenance_log::key::util::{KeyParamsType};
//! use bs::params::anykey::PubkeyParams;
//!
//! // Works with predefined types or your custom types
//! let pubkey: Key = PubkeyParams.into();
//! let pubkey: Key = PubkeyParams::key();
//!
//! // This is equivalent to using the key() method
//! assert_eq!(<bs::params::anykey::PubkeyParams as Into<Key>>::into(PubkeyParams), PubkeyParams::key());
//! ```
use crate::ops::update::OpParams;
use multicodec::Codec;
use provenance_log::{
    const_assert_valid_key,
    key::util::{KeyParams, KeyParamsType, ValidatedKeyPath},
    Key,
};

/// Public Key parameters type
pub struct PubkeyParams;

impl KeyParamsType for PubkeyParams {
    const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/pubkey");
}

impl PubkeyParams {
    /// Creates a new ed25519 private key parameters instance.
    pub fn new_ed25519() -> KeyParams {
        Self::params().codec(Codec::Ed25519Priv).build()
    }
}

/// Entry Key parameters type
pub struct EntryKeyParams;

impl KeyParamsType for EntryKeyParams {
    const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/entrykey");
}

/// Returns default entry key parameters.
pub fn default_entrykey_params() -> OpParams {
    EntryKeyParams::default_params().into()
}

impl From<KeyParams> for OpParams {
    fn from(params: KeyParams) -> Self {
        OpParams::KeyGen {
            key: Key::try_from(params.key_path()).unwrap(),
            codec: params.codec(),
            threshold: params.threshold(),
            limit: params.limit(),
            revoke: params.revoke(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::update::OpParams;

    #[test]
    fn test_pubkey_params() {
        let params = PubkeyParams::params()
            .codec(Codec::Ed25519Priv)
            .threshold(2)
            .limit(10)
            .revoke(false)
            .build();

        let op_params: OpParams = params.into();

        if let OpParams::KeyGen {
            key,
            codec,
            threshold,
            limit,
            revoke,
        } = op_params
        {
            assert_eq!(key, Key::try_from(&PubkeyParams::KEY_PATH).unwrap());
            // Or use the new helper method:
            // assert_eq!(key, PubkeyParams::key());
            assert_eq!(codec, Codec::Ed25519Priv);
            assert_eq!(threshold, 2);
            assert_eq!(limit, 10);
            assert!(!revoke);
        } else {
            panic!("Expected OpParams::KeyGen");
        }
    }

    #[test]
    fn test_entrykey_params() {
        let params = EntryKeyParams::params()
            .codec(Codec::Ed25519Priv)
            .threshold(2)
            .limit(10)
            .revoke(false)
            .build();

        let op_params: OpParams = params.into();

        if let OpParams::KeyGen {
            key,
            codec,
            threshold,
            limit,
            revoke,
        } = op_params
        {
            assert_eq!(key, Key::try_from(&EntryKeyParams::KEY_PATH).unwrap());
            // Or use the new helper method:
            // assert_eq!(key, EntryKeyParams::key());
            assert_eq!(codec, Codec::Ed25519Priv);
            assert_eq!(threshold, 2);
            assert_eq!(limit, 10);
            assert!(!revoke);
        } else {
            panic!("Expected OpParams::KeyGen");
        }
    }

    #[test]
    fn test_custom_key_path() {
        // Example of how a user could create their own key type
        struct CustomKey;

        impl KeyParamsType for CustomKey {
            const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/mycustomkey");
        }

        let params = CustomKey::params()
            .codec(Codec::Ed25519Priv)
            .threshold(3)
            .limit(5)
            .build();

        let op_params: OpParams = params.into();
        if let OpParams::KeyGen { key, .. } = op_params {
            assert_eq!(key, Key::try_from(&CustomKey::KEY_PATH).unwrap());
            // Or use the new helper method:
            // assert_eq!(key, CustomKey::key());
        } else {
            panic!("Expected OpParams::KeyGen");
        }
    }

    #[test]
    fn test_default_params() {
        let params = PubkeyParams::default_params();
        assert_eq!(params.key_path(), PubkeyParams::KEY_PATH.as_str());
        assert_eq!(params.threshold(), 1);
    }

    #[test]
    fn test_ed25519_convenience() {
        let params = PubkeyParams::new_ed25519();
        assert_eq!(params.codec(), Codec::Ed25519Priv);
    }
}

#[cfg(test)]
mod invalid_path_tests {
    use super::*;

    // This module tests compile-time validation - no actual test code is run

    #[test]
    fn test_key_params_validation_compiles() {
        // This should compile fine
        struct ValidKey;

        impl KeyParamsType for ValidKey {
            const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/valid/path");
        }

        let _ = ValidKey::default_params();

        // The following would fail to compile if uncommented:
        /*
        struct InvalidKey;

        impl KeyParamsType for InvalidKey {
            const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("invalid-no-leading-slash");
        }

        let _ = InvalidKey::default_params();
        */
    }
}
