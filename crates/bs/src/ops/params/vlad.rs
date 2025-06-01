//! Vlad Paramters for operations
use crate::ops::update::OpParams;
use multicodec::Codec;
use provenance_log::{
    const_assert_valid_key,
    key::key_paths::{ValidatedKeyParams, ValidatedKeyPath},
};
use std::num::NonZeroUsize;

/// Vlad parameters, made up of a Key and Vlad Cid fields.
///
/// # Example
///
/// ```rust
/// use multicodec::Codec;
/// use provenance_log::key::key_paths::ValidatedKeyParams;
/// use provenance_log::const_assert_valid_key;
/// use bs::ops::params::vlad::VladParams;
///
/// // Create parameters with explicit settings
/// let vlad_params = VladParams::builder()
///    .key(Codec::Ed25519Priv)
///    .hash(Codec::Sha2256)
///    .build();
/// ```
#[derive(bon::Builder, Debug, Clone)]
pub struct VladParams {
    /// [Codec] used for the [multikey::Multikey] part of the [multicid::Vlad], defaults to [Codec::Ed25519Priv].
    #[builder(default = Codec::Ed25519Priv)]
    key: Codec,
    /// [Codec] used for the  [multihash::Multihash] of the [multicid::Vlad] [multicid::Cid], defaults to [Codec::Sha2256].
    #[builder(default = Codec::Sha2256)]
    hash: Codec,
}

impl Default for VladParams {
    fn default() -> Self {
        VladParams::builder().build()
    }
}

impl ValidatedKeyParams for VladParams {
    const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/vlad/key");
}

impl VladParams {
    /// CID key path for Vlad CID
    pub const CID_KEY: ValidatedKeyPath = const_assert_valid_key!("/vlad/"); // the trailing /cid is added in open_plog()
    /// The first lock script
    pub const FIRST_LOCK_SCRIPT: &str = r#"check_signature("/entrykey", "/entry/")"#;
}

impl From<VladParams> for (OpParams, OpParams) {
    fn from(params: VladParams) -> Self {
        let key_params = OpParams::KeyGen {
            codec: params.key,
            threshold: NonZeroUsize::new(1).unwrap(), // vlad will never have threshold > 1
            key: VladParams::KEY_PATH.into(),         // the key path is always the vlad key path
            limit: NonZeroUsize::new(1).unwrap(),     // vlad will never have limit > 1
            revoke: false,                            // vlad does not support revoking keys
        };

        let cid_params = OpParams::CidGen {
            hash: params.hash,
            data: VladParams::FIRST_LOCK_SCRIPT.as_bytes().to_vec(), // data is always the first lock script
            key: VladParams::CID_KEY.into(), // the cid key is always the vlad key
            version: Codec::Cidv1,           // v1 is the latest version right now
            target: Codec::Identity,         // vlad cid is always identity
            inline: true, // vlad cid is always inline since we want to preserve the bytes in-log
        };
        (key_params, cid_params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // test builder
    #[test]
    fn test_vlad_params_builder() {
        let vlad_params = VladParams::builder()
            .key(Codec::Ed25519Priv)
            .hash(Codec::Sha2256)
            .build();

        assert_eq!(vlad_params.key, Codec::Ed25519Priv);
        assert_eq!(vlad_params.hash, Codec::Sha2256);

        let op_params: (OpParams, OpParams) = vlad_params.into();

        if let OpParams::KeyGen {
            key,
            codec,
            threshold,
            limit,
            revoke,
        } = op_params.0
        {
            assert_eq!(key, VladParams::KEY_PATH.into());
            assert_eq!(codec, Codec::Ed25519Priv);
            assert_eq!(threshold, NonZeroUsize::new(1).unwrap());
            assert_eq!(limit, NonZeroUsize::new(1).unwrap());
            assert!(!revoke);
        } else {
            panic!("Expected KeyGen OpParams");
        }

        if let OpParams::CidGen {
            key,
            version,
            target,
            hash,
            inline,
            data,
        } = op_params.1
        {
            assert_eq!(key, VladParams::CID_KEY.into());
            assert_eq!(version, Codec::Cidv1);
            assert_eq!(target, Codec::Identity);
            assert_eq!(hash, Codec::Sha2256);
            assert!(inline);
            assert_eq!(data, VladParams::FIRST_LOCK_SCRIPT.as_bytes().to_vec());
        } else {
            panic!("Expected CidGen OpParams");
        }
    }

    #[test]
    fn test_vlad_params_default() {
        let vlad_params = VladParams::default();

        assert_eq!(vlad_params.key, Codec::Ed25519Priv);
        assert_eq!(vlad_params.hash, Codec::Sha2256);

        let op_params: (OpParams, OpParams) = vlad_params.into();

        if let OpParams::KeyGen {
            key,
            codec,
            threshold,
            limit,
            revoke,
        } = op_params.0
        {
            assert_eq!(key, VladParams::KEY_PATH.into());
            assert_eq!(codec, Codec::Ed25519Priv);
            assert_eq!(threshold, NonZeroUsize::new(1).unwrap());
            assert_eq!(limit, NonZeroUsize::new(1).unwrap());
            assert!(!revoke);
        } else {
            panic!("Expected KeyGen OpParams");
        }

        if let OpParams::CidGen {
            key,
            version,
            target,
            hash,
            inline,
            data,
        } = op_params.1
        {
            assert_eq!(key, VladParams::CID_KEY.into());
            assert_eq!(version, Codec::Cidv1);
            assert_eq!(target, Codec::Identity);
            assert_eq!(hash, Codec::Sha2256);
            assert!(inline);
            assert_eq!(data, VladParams::FIRST_LOCK_SCRIPT.as_bytes().to_vec());
        } else {
            panic!("Expected CidGen OpParams");
        }
    }
}
