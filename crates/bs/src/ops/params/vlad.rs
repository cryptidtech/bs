//! Vlad Paramters for operations
use std::ops::Deref;

use crate::ops::update::OpParams;
use multicodec::Codec;
use provenance_log::Key;

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

impl VladKey {
    /// Sets the threshold for the VladKey OpParams.
    pub fn set_threshold(&mut self, threshold: u32) {
        if let OpParams::KeyGen { threshold: t, .. } = &mut self.0 {
            *t = threshold as usize;
        }
    }

    /// Sets the limit for the VladKey OpParams.
    pub fn set_limit(&mut self, limit: u32) {
        if let OpParams::KeyGen { limit: l, .. } = &mut self.0 {
            *l = limit as usize;
        }
    }
}

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

impl VladParams {
    /// Key path for Vlad operations.
    pub const KEY_PATH: &str = "/vlad/key";
    /// CID key path for Vlad CID
    pub const CID_KEY: &str = "/vlad/";
    /// The first lock script
    pub const FIRST_LOCK_SCRIPT: &str = r#"check_signature("/entrykey", "/entry/")"#;

    /// Makes a VladConfig with default key and cid paths.
    pub fn new(key_codec: KeyCodec, hash_codec: HashCodec) -> Self {
        let key = VladKey(OpParams::KeyGen {
            key: Key::try_from(Self::KEY_PATH).unwrap(),
            codec: *key_codec,
            threshold: 0,
            limit: 0,
            revoke: false,
        });

        let cid = VladCid(OpParams::CidGen {
            key: Key::try_from(Self::CID_KEY).unwrap(),
            version: Codec::Cidv1,
            target: Codec::Identity,
            hash: *hash_codec,
            inline: true,
            data: Self::FIRST_LOCK_SCRIPT.as_bytes().to_vec(),
        });

        VladParams { key, cid }
    }

    /// Sets the threshold for the VladKey OpParams.
    pub fn with_threshold(&mut self, threshold: u32) {
        self.key.set_threshold(threshold);
    }

    /// Sets the limit for the VladKey OpParams.
    pub fn with_limit(&mut self, limit: u32) {
        self.key.set_limit(limit);
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
                key: Key::try_from(VladParams::KEY_PATH).unwrap(),
                codec: Codec::Identity,
                threshold: 0,
                limit: 0,
                revoke: false,
            }
        );
        assert_eq!(
            vlad_config.cid.0,
            OpParams::CidGen {
                key: Key::try_from(VladParams::CID_KEY).unwrap(),
                version: Codec::Cidv1,
                target: Codec::Identity,
                hash: Codec::Sha2256,
                inline: true,
                data: VladParams::FIRST_LOCK_SCRIPT.as_bytes().to_vec(),
            }
        );
    }
}
