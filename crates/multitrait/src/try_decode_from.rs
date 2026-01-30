// SPDX-License-Idnetifier: Apache-2.0
use crate::Error;
use unsigned_varint::decode;

/// This trait tries to decode a type from a slice of bytes. This primarily
/// used for types encoded with varuint values.
pub trait TryDecodeFrom<'a>: Sized {
    /// The error type emited on failure
    type Error;

    /// Try to decode the type from a slice of bytes returning the object and
    /// the reference to the rest of the slice
    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error>;
}

/// Try to decode a varuint encoded bool
impl<'a> TryDecodeFrom<'a> for bool {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (v, ptr) = decode::u8(bytes).map_err(Self::Error::UnsignedVarintDecode)?;
        Ok(((v != 0), ptr))
    }
}

/// Try to decode a varuint encoded u8
impl<'a> TryDecodeFrom<'a> for u8 {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        decode::u8(bytes).map_err(Self::Error::UnsignedVarintDecode)
    }
}

/// Try to decode a varuint encoded u16
impl<'a> TryDecodeFrom<'a> for u16 {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        decode::u16(bytes).map_err(Self::Error::UnsignedVarintDecode)
    }
}

/// Try to decode a varuint encoded u32
impl<'a> TryDecodeFrom<'a> for u32 {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        decode::u32(bytes).map_err(Self::Error::UnsignedVarintDecode)
    }
}

/// Try to decode a varuint encoded u64
impl<'a> TryDecodeFrom<'a> for u64 {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        decode::u64(bytes).map_err(Self::Error::UnsignedVarintDecode)
    }
}

/// Try to decode a varuint encoded u128
impl<'a> TryDecodeFrom<'a> for u128 {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        decode::u128(bytes).map_err(Self::Error::UnsignedVarintDecode)
    }
}

/// Try to decode a varuint encoded u128
impl<'a> TryDecodeFrom<'a> for usize {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        decode::usize(bytes).map_err(Self::Error::UnsignedVarintDecode)
    }
}

impl<const N: usize> TryDecodeFrom<'_> for [u8; N] {
    type Error = Error;

    fn try_decode_from(bytes: &'_ [u8]) -> Result<([u8; N], &'_ [u8]), Self::Error> {
        if bytes.len() < 32 {
            return Err(Error::UnsignedVarintDecode(decode::Error::Overflow));
        }
        let a = <[u8; N]>::try_from(bytes)
            .map_err(|_| Self::Error::UnsignedVarintDecode(decode::Error::Insufficient))?;
        Ok((a, &bytes[32..]))
    }
}
