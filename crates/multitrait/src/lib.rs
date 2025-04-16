// SPDX-License-Idnetifier: Apache-2.0
//! # Multiutil
//!
//! A set of traits that are helpful for implementing
//! [multiformats](https://github.com/multiformats/multiformats) types in Rust.
#![warn(missing_docs)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Errors generated from the implementations
pub mod error;
pub use error::Error;

/// EncodeInto trait
pub mod enc_into;
pub use enc_into::EncodeInto;

/// Null and TryNull traits
pub mod null;
pub use null::{Null, TryNull};

/// TryDecodeFrom trait
pub mod try_decode_from;
pub use try_decode_from::TryDecodeFrom;

/// one-stop shop for all exported symbols
pub mod prelude {
    pub use super::{enc_into::*, null::*, try_decode_from::*};
}

#[cfg(test)]
mod test {
    use super::prelude::*;

    #[test]
    fn test_bool() {
        let tbuf = true.encode_into();
        let (tval, _) = bool::try_decode_from(&tbuf).unwrap();
        assert_eq!(true, tval);
        let fbuf = false.encode_into();
        let (fval, _) = bool::try_decode_from(&fbuf).unwrap();
        assert_eq!(false, fval);
    }

    #[test]
    fn test_u8() {
        let buf = 0xff_u8.encode_into();
        let (num, _) = u8::try_decode_from(&buf).unwrap();
        assert_eq!(0xff_u8, num);
    }

    #[test]
    fn test_u16() {
        let buf = 0xffee_u16.encode_into();
        let (num, _) = u16::try_decode_from(&buf).unwrap();
        assert_eq!(0xffee_u16, num);
    }

    #[test]
    fn test_u32() {
        let buf = 0xffeeddcc_u32.encode_into();
        let (num, _) = u32::try_decode_from(&buf).unwrap();
        assert_eq!(0xffeeddcc_u32, num);
    }

    #[test]
    fn test_u64() {
        let buf = 0xffeeddcc_bbaa9988_u64.encode_into();
        let (num, _) = u64::try_decode_from(&buf).unwrap();
        assert_eq!(0xffeeddcc_bbaa9988_u64, num);
    }

    #[test]
    fn test_u128() {
        let buf = 0xffeeddcc_bbaa9988_77665544_33221100_u128.encode_into();
        let (num, _) = u128::try_decode_from(&buf).unwrap();
        assert_eq!(0xffeeddcc_bbaa9988_77665544_33221100_u128, num);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn test_usize() {
        let buf = 0xffeeddcc_bbaa9988_usize.encode_into();
        let (num, _) = usize::try_decode_from(&buf).unwrap();
        assert_eq!(0xffeeddcc_bbaa9988_usize, num);
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn test_usize() {
        let buf = 0xffeeddcc_usize.encode_into();
        let (num, _) = usize::try_decode_from(&buf).unwrap();
        assert_eq!(0xffeeddcc_usize, num);
    }

    struct Foo(usize);

    impl Null for Foo {
        fn null() -> Self {
            Foo(0)
        }
        fn is_null(&self) -> bool {
            self.0 == 0
        }
    }

    impl TryNull for Foo {
        type Error = &'static str;

        fn try_null() -> Result<Self, Self::Error> {
            Ok(Foo(0))
        }
        fn is_null(&self) -> bool {
            self.0 == 0
        }
    }

    #[test]
    fn test_null_value() {
        let f = Foo::null();
        assert!(Null::is_null(&f));
    }

    #[test]
    fn test_try_null_value() {
        let f = Foo::try_null().unwrap();
        assert!(TryNull::is_null(&f));
    }
}
