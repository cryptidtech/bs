// SPDX-License-Idnetifier: Apache-2.0
use crate::{error::AttributesError, Error};
use multitrait::{EncodeInto, TryDecodeFrom};
use std::fmt;

/// enum of attribute identifiers. this is here to avoid collisions between
/// different codecs and encryption schemes. these are the common set of
/// attribute identifiers use in Multikeys
#[repr(u8)]
#[derive(Clone, Copy, Hash, Ord, PartialOrd, PartialEq, Eq)]
pub enum AttrId {
    /// bool attribute signaling if the key is encrypted
    KeyIsEncrypted,
    /// the key data
    KeyData,
    /// the cipher codec used to encrypt the key, if encrypted
    CipherCodec,
    /// the length of the cipher codec key in bytes, if encrypted
    CipherKeyLen,
    /// the nonce used to encrypt the key, if encrypted
    CipherNonce,
    /// the codec used to derive the encryption key, if encrypted
    KdfCodec,
    /// the salt used to derive the encryption key, if encrypted
    KdfSalt,
    /// the rounds used to derive the encryption key, if encrypted
    KdfRounds,
    /// the threshold key threshold
    Threshold,
    /// the threshold key limit
    Limit,
    /// the theshold key share identifier
    ShareIdentifier,
    /// codec-specific threshold key data
    ThresholdData,
}

impl AttrId {
    /// Get the code for the attribute id
    pub fn code(&self) -> u8 {
        (*self).into()
    }

    /// Convert the attribute id to &str
    pub fn as_str(&self) -> &str {
        match self {
            AttrId::KeyIsEncrypted => "key-is-encrypted",
            AttrId::KeyData => "key-data",
            AttrId::CipherCodec => "cipher-codec",
            AttrId::CipherKeyLen => "cipher-key-len",
            AttrId::CipherNonce => "cipher-nonce",
            AttrId::KdfCodec => "kdf-codec",
            AttrId::KdfSalt => "kdf-salt",
            AttrId::KdfRounds => "kdf-rounds",
            AttrId::Threshold => "threshold",
            AttrId::Limit => "limit",
            AttrId::ShareIdentifier => "share-identifier",
            AttrId::ThresholdData => "threshold-data",
        }
    }
}

impl From<AttrId> for u8 {
    fn from(val: AttrId) -> Self {
        val as u8
    }
}

impl TryFrom<u8> for AttrId {
    type Error = Error;

    fn try_from(c: u8) -> Result<Self, Self::Error> {
        match c {
            0 => Ok(AttrId::KeyIsEncrypted),
            1 => Ok(AttrId::KeyData),
            2 => Ok(AttrId::CipherCodec),
            3 => Ok(AttrId::CipherKeyLen),
            4 => Ok(AttrId::CipherNonce),
            5 => Ok(AttrId::KdfCodec),
            6 => Ok(AttrId::KdfSalt),
            7 => Ok(AttrId::KdfRounds),
            8 => Ok(AttrId::Threshold),
            9 => Ok(AttrId::Limit),
            10 => Ok(AttrId::ShareIdentifier),
            11 => Ok(AttrId::ThresholdData),
            _ => Err(AttributesError::InvalidAttributeValue(c).into()),
        }
    }
}

impl From<AttrId> for Vec<u8> {
    fn from(val: AttrId) -> Self {
        let v: u8 = val.into();
        v.encode_into()
    }
}

impl<'a> TryFrom<&'a [u8]> for AttrId {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (id, _) = Self::try_decode_from(bytes)?;
        Ok(id)
    }
}

impl<'a> TryDecodeFrom<'a> for AttrId {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (code, ptr) = u8::try_decode_from(bytes)?;
        Ok((AttrId::try_from(code)?, ptr))
    }
}

impl TryFrom<&str> for AttrId {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_ascii_lowercase().as_str() {
            "key-is-encrypted" => Ok(AttrId::KeyIsEncrypted),
            "key-data" => Ok(AttrId::KeyData),
            "cipher-codec" => Ok(AttrId::CipherCodec),
            "cipher-key-len" => Ok(AttrId::CipherKeyLen),
            "cipher-nonce" => Ok(AttrId::CipherNonce),
            "kdf-codec" => Ok(AttrId::KdfCodec),
            "kdf-salt" => Ok(AttrId::KdfSalt),
            "kdf-rounds" => Ok(AttrId::KdfRounds),
            "threshold" => Ok(AttrId::Threshold),
            "limit" => Ok(AttrId::Limit),
            "share-identifier" => Ok(AttrId::ShareIdentifier),
            "threshold-data" => Ok(AttrId::ThresholdData),
            _ => Err(AttributesError::InvalidAttributeName(s.to_string()).into()),
        }
    }
}

impl fmt::Display for AttrId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
