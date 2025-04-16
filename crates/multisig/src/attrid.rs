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
    /// the signature data
    SigData,
    /// the payload encoding
    PayloadEncoding,
    /// signing scheme
    Scheme,
    /// threshold signature threshold
    Threshold,
    /// threshold signature limit
    Limit,
    /// threshold signature share identifier
    ShareIdentifier,
    /// codec-specific threshold signature data
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
            Self::SigData => "sig-data",
            Self::PayloadEncoding => "payload-encoding",
            Self::Scheme => "scheme",
            Self::Threshold => "threshold",
            Self::Limit => "limit",
            Self::ShareIdentifier => "share-identifier",
            Self::ThresholdData => "threshold-data",
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
            0 => Ok(Self::SigData),
            1 => Ok(Self::PayloadEncoding),
            2 => Ok(Self::Scheme),
            3 => Ok(Self::Threshold),
            4 => Ok(Self::Limit),
            5 => Ok(Self::ShareIdentifier),
            6 => Ok(Self::ThresholdData),
            _ => Err(AttributesError::InvalidAttributeValue(c).into()),
        }
    }
}

impl From<AttrId> for Vec<u8> {
    fn from(val: AttrId) -> Self {
        val.code().encode_into()
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
        Ok((Self::try_from(code)?, ptr))
    }
}

impl TryFrom<&str> for AttrId {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_ascii_lowercase().as_str() {
            "sig-data" => Ok(Self::SigData),
            "payload-encoding" => Ok(Self::PayloadEncoding),
            "scheme" => Ok(Self::Scheme),
            "threshold" => Ok(Self::Threshold),
            "limit" => Ok(Self::Limit),
            "share-identifier" => Ok(Self::ShareIdentifier),
            "threshold-data" => Ok(Self::ThresholdData),
            _ => Err(AttributesError::InvalidAttributeName(s.to_string()).into()),
        }
    }
}

impl fmt::Display for AttrId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
