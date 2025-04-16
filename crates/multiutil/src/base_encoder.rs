// SPDX-License-Idnetifier: Apache-2.0
use crate::{
    base_name,
    error::{BaseEncodedError, BaseEncoderError},
    prelude::Base,
    BaseIter, Error,
};

/// a trait for base encoding implementations
pub trait BaseEncoder {
    /// convert a &[u8] to a base encoded value
    fn to_base_encoded(base: Base, b: &[u8]) -> String;

    /// convert a base encoded value to a Vec<u8>
    fn from_base_encoded(s: &str) -> Result<Vec<(Base, Vec<u8>)>, Error>;

    /// get the debug string for the given base
    fn debug_string(base: Base) -> String;

    /// get the preferred base encoding for this encoder
    fn preferred_encoding(base: Base) -> Base;
}

/// a multibase encoder implementation for use as the default encoder
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultibaseEncoder {}

impl BaseEncoder for MultibaseEncoder {
    fn to_base_encoded(base: Base, b: &[u8]) -> String {
        multibase::encode(base, b)
    }
    fn from_base_encoded(s: &str) -> Result<Vec<(Base, Vec<u8>)>, Error> {
        // try permissive multibase decoding
        Ok(vec![
            multibase::decode(s, false).map_err(|_| BaseEncodedError::ValueFailed)?
        ])
    }
    fn debug_string(base: Base) -> String {
        format!("{} ('{}')", base_name(base), base.code())
    }
    fn preferred_encoding(base: Base) -> Base {
        base
    }
}

/// a bare Base58Btc encoder implementation for use with legacy CIDs
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Base58Encoder {}

impl BaseEncoder for Base58Encoder {
    fn to_base_encoded(_base: Base, b: &[u8]) -> String {
        Base::Base58Btc.encode(b)
    }
    fn from_base_encoded(s: &str) -> Result<Vec<(Base, Vec<u8>)>, Error> {
        // try strict Base58Btc decoding
        match Base::Base58Btc.decode(s, true) {
            Ok(v) => Ok(vec![(Base::Base58Btc, v)]),
            Err(e) => Err(BaseEncoderError::Base58(format!("{:?}", e)).into()),
        }
    }
    fn debug_string(_base: Base) -> String {
        format!(
            "{} ('{}')",
            base_name(Base::Base58Btc),
            Base::Base58Btc.code()
        )
    }
    fn preferred_encoding(_base: Base) -> Base {
        Base::Base58Btc
    }
}

/// a speculative encoder that tries to detect the correct encoding and decode it
/// encoding is always done using multibase so this does not support symetric
/// decode/encode round trips. this is useful for decoding CIDs that might be
/// base58 encoded "legacy" CIDs but alsy may be multibase encoded CIDs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DetectedEncoder {}

impl BaseEncoder for DetectedEncoder {
    fn to_base_encoded(base: Base, b: &[u8]) -> String {
        multibase::encode(base, b)
    }
    fn from_base_encoded(s: &str) -> Result<Vec<(Base, Vec<u8>)>, Error> {
        // first try permissive multibase decoding
        if let Ok((base, data)) = multibase::decode(s, false) {
            return Ok(vec![(base, data)]);
        }

        // start at the Identity base so we skip it
        let iter: BaseIter = Base::Identity.into();

        // next try "naked" encoding in increasing symbol space size order.
        // these have to be strict decodings to avoid confusion
        let mut v = Vec::default();
        for encoding in iter {
            if let Ok(data) = encoding.decode(s, true) {
                v.push((encoding, data));
            }
        }
        if v.is_empty() {
            // raise an error
            Err(BaseEncodedError::ValueFailed.into())
        } else {
            Ok(v)
        }
    }
    fn debug_string(base: Base) -> String {
        format!("{} ('{}')", base_name(base), base.code())
    }
    fn preferred_encoding(base: Base) -> Base {
        base
    }
}
