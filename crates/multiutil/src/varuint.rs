// SPDX-License-Idnetifier: Apache-2.0
use crate::{BaseEncoded, EncodingInfo, Error};
use core::{fmt, ops};
use multibase::Base;
use multitrait::{EncodeInto, TryDecodeFrom};

/// A wrapper type to handle serde of numeric types as varuint bytes
#[derive(Clone, PartialEq)]
pub struct Varuint<T>(pub T);

/// type alias for a Varuint base encoded to/from string
pub type EncodedVaruint<T> = BaseEncoded<Varuint<T>>;

impl<T> Varuint<T>
where
    T: EncodeInto + for<'a> TryDecodeFrom<'a>,
{
    /// create a new encoded varuint
    pub fn encoded_new(base: Base, t: T) -> EncodedVaruint<T> {
        BaseEncoded::new(base, Self(t))
    }

    /// consume self and return inner value
    pub fn to_inner(self) -> T {
        self.0
    }
}

impl<T> Default for Varuint<T>
where
    T: Default,
{
    fn default() -> Self {
        Self(T::default())
    }
}

impl<T> fmt::Debug for Varuint<T>
where
    T: EncodeInto,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0.encode_into().as_slice())
    }
}

impl<T> ops::Deref for Varuint<T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> EncodingInfo for Varuint<T> {
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    fn encoding(&self) -> Base {
        Base::Base16Lower
    }
}

impl<T> From<Varuint<T>> for Vec<u8>
where
    T: EncodeInto,
{
    fn from(vu: Varuint<T>) -> Vec<u8> {
        vu.0.encode_into()
    }
}

impl<'a, T> TryFrom<&'a [u8]> for Varuint<T>
where
    T: TryDecodeFrom<'a>,
{
    type Error = Error;

    fn try_from(s: &'a [u8]) -> Result<Self, Error> {
        let (t, _) = Self::try_decode_from(s)?;
        Ok(t)
    }
}

impl<'a, T> TryDecodeFrom<'a> for Varuint<T>
where
    T: TryDecodeFrom<'a>,
{
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (t, ptr) =
            T::try_decode_from(bytes).map_err(|_| Error::custom("failed to decode varuint"))?;
        Ok((Self(t), ptr))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_default() {
        let v = Varuint::<u64>::default();
        assert_eq!(0_u64, *v);
    }

    #[test]
    fn test_to_inner() {
        let v = Varuint(42_u64);
        assert_eq!(42_u64, v.to_inner());
    }

    #[test]
    fn test_default_round_trip() {
        let v1 = Varuint::<u64>::default();
        let v: Vec<u8> = v1.clone().into();
        let v2 = Varuint::<u64>::try_from(v.as_slice()).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_encode_decode_round_trip() {
        let v1 = Varuint(42_u64);
        let (v2, _) = Varuint::<u64>::try_decode_from(&v1.encode_into()).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_into_tryfrom_round_trip() {
        let v1 = Varuint(42_u64);
        let data: Vec<u8> = v1.clone().into();
        let v2 = Varuint::<u64>::try_from(data.as_slice()).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_debug() {
        let v = Varuint(0xed_u64);
        assert_eq!("[237, 1]".to_string(), format!("{:?}", v));
    }
}
