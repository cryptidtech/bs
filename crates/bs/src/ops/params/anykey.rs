//! Common and Custom Key Parameters Types, for [OpParams::KeyGen] Operation Parameters.
//!
//! This module provides some concrete implementations of the generic way to define parameters for any key type based on
//! a path that identifies the key.
//!
//! # Creating Custom Key Types
//!
//! You can easily create your own key parameter types by using the [ValidatedKeyParams] trait:
//!
//! ```rust
//! use provenance_log::key::key_paths::{ValidatedKeyParams, KeyParams};
//! use provenance_log::const_assert_valid_key;
//! use provenance_log::key::key_paths::ValidatedKeyPath;
//! use bs::ops::update::OpParams;
//! use multicodec::Codec;
//! use std::num::NonZero;
//!
//! pub struct MyCustomKeyParams;
//!
//! impl ValidatedKeyParams for MyCustomKeyParams {
//!     const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/my/special/key");
//! }
//!
//! // Create parameters with some details
//! let custom_key_params = MyCustomKeyParams::builder()
//!    .codec(Codec::Ed25519Priv)
//!    .threshold(NonZero::new(1).unwrap())
//!    .limit(NonZero::new(1).unwrap())
//!    .revoke(false)
//!    .build();
//!
//! // Convert parameters to OpParams enum
//! let params: OpParams = custom_key_params.into();
//!
//! // You can destructure the OpParams to access the key parameters
//! let OpParams::KeyGen {
//!    key,
//!    codec,
//!    threshold,
//!    limit,
//!    revoke,
//!    } = params else {
//!    panic!("Expected OpParams::KeyGen");
//!    };
//! ```
//!
//! The blanket implementation to convert any type implementing `ValidatedKeyParams` into a `Key`
//! can also be used on these concrete types.
//!
//! # Example
//!
//! ```rust
//! use provenance_log::Key;
//! use provenance_log::key::key_paths::{ValidatedKeyParams};
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
use provenance_log::{
    const_assert_valid_key,
    key::key_paths::{KeyParams, ValidatedKeyParams, ValidatedKeyPath},
};

/// Public Key parameters type
pub struct PubkeyParams;

impl ValidatedKeyParams for PubkeyParams {
    const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/pubkey");
}

/// Entry Key parameters type
pub struct EntryKeyParams;

impl ValidatedKeyParams for EntryKeyParams {
    const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/entrykey");
}

impl From<KeyParams> for OpParams {
    fn from(params: KeyParams) -> Self {
        OpParams::KeyGen {
            key: params.key_path().clone(),
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
    use multicodec::Codec;
    use provenance_log::Key;
    use std::num::NonZeroUsize;

    #[test]
    fn test_pubkey_params() {
        let params = PubkeyParams::builder().codec(Codec::Ed25519Priv).build();

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
            assert_eq!(threshold, NonZeroUsize::new(1).unwrap());
            assert_eq!(limit, NonZeroUsize::new(1).unwrap());
            assert!(!revoke);
        } else {
            panic!("Expected OpParams::KeyGen");
        }
    }

    #[test]
    fn test_entrykey_params() {
        let params = EntryKeyParams::builder().codec(Codec::Ed25519Priv).build();

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
            assert_eq!(threshold, NonZeroUsize::new(1).unwrap());
            assert_eq!(limit, NonZeroUsize::new(1).unwrap());
            assert!(!revoke);
        } else {
            panic!("Expected OpParams::KeyGen");
        }
    }

    #[test]
    fn test_custom_key_path() {
        // Example of how a user could create their own key type
        struct CustomKey;

        impl ValidatedKeyParams for CustomKey {
            const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/mycustomkey");
        }

        let params = CustomKey::builder().codec(Codec::Ed25519Priv).build();

        let op_params: OpParams = params.into();
        if let OpParams::KeyGen { key, .. } = op_params {
            assert_eq!(key, Key::try_from(&CustomKey::KEY_PATH).unwrap());
            // Or use the new helper method:
            // assert_eq!(key, CustomKey::key());
        } else {
            panic!("Expected OpParams::KeyGen");
        }
    }
}
