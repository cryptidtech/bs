// SPDX-License-Idnetifier: Apache-2.0
use crate::{BaseEncoded, EncodingInfo, Error};
use core::{fmt, ops};
use multibase::Base;
use multitrait::prelude::{EncodeInto, TryDecodeFrom};

/// A wrapper type to handle serde of byte arrays as bytes
#[derive(Clone, Default, PartialEq)]
pub struct Varbytes(pub Vec<u8>);

/// type alias for a Varbytes base encoded to/from string
pub type EncodedVarbytes = BaseEncoded<Varbytes>;

impl Varbytes {
    /// create an encoded varbytes
    pub fn encoded_new(base: Base, v: Vec<u8>) -> EncodedVarbytes {
        BaseEncoded::new(base, Varbytes(v))
    }

    /// consume self and return inner vec
    pub fn to_inner(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for Varbytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.encode_into().as_slice())
    }
}

impl ops::Deref for Varbytes {
    type Target = Vec<u8>;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EncodingInfo for Varbytes {
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    fn encoding(&self) -> Base {
        Base::Base16Lower
    }
}

impl From<Varbytes> for Vec<u8> {
    fn from(vb: Varbytes) -> Vec<u8> {
        vb.encode_into()
    }
}

impl EncodeInto for Varbytes {
    fn encode_into(&self) -> Vec<u8> {
        let mut v = self.0.len().encode_into();
        v.append(&mut self.0.clone());
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for Varbytes {
    type Error = Error;

    fn try_from(s: &'a [u8]) -> Result<Self, Error> {
        let (v, _) = Self::try_decode_from(s)?;
        Ok(v)
    }
}

impl<'a> TryDecodeFrom<'a> for Varbytes {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (len, ptr) = usize::try_decode_from(bytes)?;
        let v = ptr[..len].to_vec();
        let ptr = &ptr[len..];
        Ok((Self(v), ptr))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_default() {
        let v = Varbytes::default();
        assert_eq!(Vec::<u8>::default(), *v);
    }

    #[test]
    fn test_to_inner() {
        let v = Varbytes(vec![1, 2, 3]);
        assert_eq!(vec![1, 2, 3], v.to_inner());
    }

    #[test]
    fn test_default_round_trip() {
        let v1 = Varbytes::default();
        let v: Vec<u8> = v1.clone().into();
        let v2 = Varbytes::try_from(v.as_slice()).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_encode_decode_round_trip() {
        let v1 = Varbytes(vec![1, 2, 3]);
        let (v2, _) = Varbytes::try_decode_from(&v1.encode_into()).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_into_tryfrom_round_trip() {
        let v1 = Varbytes(vec![1, 2, 3]);
        let data: Vec<u8> = v1.clone().into();
        let v2 = Varbytes::try_from(data.as_slice()).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_debug() {
        let v = Varbytes(vec![1, 2, 3]);
        assert_eq!("[3, 1, 2, 3]".to_string(), format!("{:?}", v));
    }
}
