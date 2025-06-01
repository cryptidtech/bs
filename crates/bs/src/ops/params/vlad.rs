//! Vlad Paramters for operations
use std::{num::NonZeroUsize, ops::Deref};

use crate::ops::update::OpParams;
use multicodec::Codec;
use provenance_log::{
    const_assert_valid_key,
    key::key_paths::{ValidatedKeyParams, ValidatedKeyPath},
};

/// NewType wrapper around KeyCodec
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyCodec(pub Codec);

/// NewType wrapper around HashCodec
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HashCodec(pub Codec);
/// NewType Wrapper around VladKey OpParams
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VladKey(pub OpParams);

/// NewType Wrapper around VladCid OpParams
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VladCid(pub OpParams);

impl Deref for VladKey {
    type Target = OpParams;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for VladCid {
    type Target = OpParams;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for KeyCodec {
    type Target = Codec;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for HashCodec {
    type Target = Codec;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
/// Vlad parameters, made up of a Key and Vlad Cid fields.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VladParams {
    key: VladKey,
    cid: VladCid,
}

impl Default for VladParams {
    fn default() -> Self {
        let key_codec = KeyCodec(Codec::Ed25519Priv);
        let hash_codec = HashCodec(Codec::Sha2256);
        Self::new(key_codec, hash_codec)
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

    /// Makes a VladConfig with default key and cid paths.
    pub fn new(key_codec: KeyCodec, hash_codec: HashCodec) -> Self {
        let key = VladKey(OpParams::KeyGen {
            codec: *key_codec,
            threshold: NonZeroUsize::new(1).unwrap(), // vlad will never have threshold > 1
            key: Self::KEY_PATH.into(),               // the key path is always the vlad key path
            limit: NonZeroUsize::new(1).unwrap(),     // vlad will never have limit > 1
            revoke: false,                            // vlad does not support revoking keys
        });

        let cid = VladCid(OpParams::CidGen {
            hash: *hash_codec,
            data: Self::FIRST_LOCK_SCRIPT.as_bytes().to_vec(), // data is always the first lock script
            key: Self::CID_KEY.into(),                         // the cid key is always the vlad key
            version: Codec::Cidv1,                             // v1 is the latest version right now
            target: Codec::Identity,                           // vlad cid is always identity
            inline: true, // vlad cid is always inline since we want to preserve the bytes in-log
        });

        VladParams { key, cid }
    }
}

impl From<VladParams> for (OpParams, OpParams) {
    fn from(params: VladParams) -> Self {
        (params.key.0, params.cid.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vlad_config_new() {
        let key_codec = KeyCodec(Codec::Identity);
        let hash_codec = HashCodec(Codec::Sha2256);
        let vlad_config = VladParams::new(key_codec, hash_codec);

        assert_eq!(
            vlad_config.key.0,
            OpParams::KeyGen {
                key: VladParams::KEY_PATH.into(),
                codec: Codec::Identity,
                threshold: NonZeroUsize::new(1).unwrap(),
                limit: NonZeroUsize::new(1).unwrap(),
                revoke: false,
            }
        );
        assert_eq!(
            vlad_config.cid.0,
            OpParams::CidGen {
                key: VladParams::CID_KEY.into(),
                version: Codec::Cidv1,
                target: Codec::Identity,
                hash: Codec::Sha2256,
                inline: true,
                data: VladParams::FIRST_LOCK_SCRIPT.as_bytes().to_vec(),
            }
        );
    }
}
