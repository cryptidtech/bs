// SPDX-License-Idnetifier: Apache-2.0
use crate::{BaseEncoded, EncodingInfo, Error};
use core::{fmt, ops};
use multibase::Base;
use multitrait::prelude::{EncodeInto, TryDecodeFrom};
use std::collections::VecDeque;

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

impl From<&Varbytes> for Vec<u8> {
    fn from(vb: &Varbytes) -> Vec<u8> {
        vb.encode_into()
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

/// The copy-free Varbytes encoding iterator
pub struct VarbytesIter<'a> {
    slice: &'a [u8],
    state: VarbytesIterState,
}

/// The state of the iterator
#[derive(Clone)]
enum VarbytesIterState {
    /// The length of the slice encoded as an unsigned varint
    Length(VecDeque<u8>),
    /// The index into the slice
    Bytes(usize),
    /// The end of the slice
    End,
}

// NOTE: we have to explicitly handle Vec<u8> and &[u8] because there is no common trait that
// includes the `len` method that both impl. If there was a trait, we could make this generic on T
// where T: AsRef<[u8]> + MythicalTraitWithLen

impl<'a> From<&'a Vec<u8>> for VarbytesIter<'a> {
    fn from(v: &'a Vec<u8>) -> Self {
        Self::from(v.as_slice())
    }
}

impl<'a> From<&'a [u8]> for VarbytesIter<'a> {
    fn from(v: &'a [u8]) -> Self {
        let mut length = VecDeque::new();
        length.extend(&v.len().encode_into());
        Self {
            slice: v,
            state: VarbytesIterState::Length(length),
        }
    }
}

impl Iterator for VarbytesIter<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.state {
            VarbytesIterState::Length(length) => {
                if length.is_empty() {
                    self.state = VarbytesIterState::Bytes(0);
                    return self.next();
                }
                length.pop_front()
            }
            VarbytesIterState::Bytes(index) => {
                if *index >= self.slice.len() {
                    self.state = VarbytesIterState::End;
                    return None;
                }
                let byte = self.slice[*index];
                *index += 1;
                Some(byte)
            }
            VarbytesIterState::End => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use test_log::test;
    use tracing::{span, Level};

    #[test]
    fn test_default() {
        let _s = span!(Level::INFO, "test_default").entered();
        let v = Varbytes::default();
        assert_eq!(Vec::<u8>::default(), *v);
    }

    #[test]
    fn test_to_inner() {
        let _s = span!(Level::INFO, "test_to_inner").entered();
        let v = Varbytes(vec![1, 2, 3]);
        assert_eq!(vec![1, 2, 3], v.to_inner());
    }

    #[test]
    fn test_default_round_trip() {
        let _s = span!(Level::INFO, "test_default_round_trip").entered();
        let v1 = Varbytes::default();
        let v: Vec<u8> = (&v1).into();
        let v2 = Varbytes::try_from(v.as_slice()).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_encode_decode_round_trip() {
        let _s = span!(Level::INFO, "test_encode_decode_round_trip").entered();
        let v1 = Varbytes(vec![1, 2, 3]);
        let (v2, _) = Varbytes::try_decode_from(&v1.encode_into()).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_into_tryfrom_round_trip() {
        let _s = span!(Level::INFO, "test_into_tryfrom_round_trip").entered();
        let v1 = Varbytes(vec![1, 2, 3]);
        let data: Vec<u8> = (&v1).into();
        let v2 = Varbytes::try_from(data.as_slice()).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_debug() {
        let _s = span!(Level::INFO, "test_debug").entered();
        let v = Varbytes(vec![1, 2, 3]);
        assert_eq!("[3, 1, 2, 3]".to_string(), format!("{:?}", v));
    }

    #[test]
    fn test_iterator() {
        let _s = span!(Level::INFO, "test_iterator").entered();
        let v = vec![1, 2, 3];
        let mut iter = VarbytesIter::from(&v);
        assert_eq!(Some(3), iter.next());
        assert_eq!(Some(1), iter.next());
        assert_eq!(Some(2), iter.next());
        assert_eq!(Some(3), iter.next());
        assert_eq!(None, iter.next());
    }

    #[test]
    fn test_iterator_large() {
        let _s = span!(Level::INFO, "test_iterator_large").entered();
        let v = vec![1; 1000];
        let mut iter = VarbytesIter::from(&v);
        assert_eq!(Some(0xe8), iter.next());
        assert_eq!(Some(0x07), iter.next());
        for _ in 0..1000 {
            assert_eq!(Some(1), iter.next());
        }
        assert_eq!(None, iter.next());
    }
}
