// SPDX-License-Identifier: MIT or Apache-2.0
//!
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
#![allow(missing_docs)]
use crate::Error;
use core::{
    fmt,
    hash::{Hash, Hasher},
};
use multitrait::{EncodeInto, Null, TryDecodeFrom};

macro_rules! build_codec_enum {
    {$( $val:expr => ($i:ident, $s:expr), )*} => {

        /// Codecs from the multicodec table
        #[allow(non_camel_case_types)]
        #[derive(Clone, Copy, Default, Eq, Ord, PartialEq, PartialOrd)]
        #[non_exhaustive]
        pub enum Codec {
            #[default]
            $( $i, )*
        }

        /// Convert from the canonical string name of the multicodec to the
        /// associated enum/value.
        impl TryFrom<&str> for Codec {
            type Error = Error;

            fn try_from(s: &str) -> Result<Self, Self::Error> {
                match s {
                    $( $s => Ok(Codec::$i), )*
                    _ => Err(Error::InvalidName(s.to_string())),
                }
            }
        }

        /// Convert a Codec into a type that implements AsRef<str>
        impl From<Codec> for &str {
            fn from(codec: Codec) -> &'static str {
                match codec {
                    $( Codec::$i => $s, )*
                }
            }
        }

        /// Convert from the value of the multicodec to the associated enum/value.
        impl TryFrom<u64> for Codec {
            type Error = Error;

            fn try_from(v: u64) -> Result<Self, Self::Error> {
                match v {
                    $( $val => Ok(Codec::$i), )*
                    _ => Err(Error::InvalidValue(v)),
                }
            }
        }

        /// Convert a Codec into a u64
        impl From<Codec> for u64 {
            fn from(codec: Codec) -> u64 {
                match codec {
                    $( Codec::$i => $val, )*
                }
            }
        }

        impl Hash for Codec {
            fn hash<H: Hasher>(&self, state: &mut H) {
                let v: Vec<u8> = self.clone().into();
                v.hash(state);
            }
        }

        /// Serialize a Codec as a unsigned varint in a Vec<u8>
        impl From<Codec> for Vec<u8> {
            fn from(codec: Codec) -> Vec<u8> {
                let v: u64 = codec.into();
                v.encode_into()
            }
        }

        /// Try to deserialized a Codec from an unsigned varint byte slice
        impl<'a> TryFrom<&'a [u8]> for Codec {
            type Error = Error;

            fn try_from(bytes: &'a [u8]) -> Result<Codec, Error> {
                let (code, _) = u64::try_decode_from(bytes)?;
                Codec::try_from(code)
            }
        }

        /// Try to deserialized a Codec from an unsigned varint byte slice and
        /// also return the position in the byte slice after the value
        impl<'a> TryDecodeFrom<'a> for Codec {
            type Error = Error;

            fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
                let (code, ptr) = u64::try_decode_from(bytes)?;
                Ok((Codec::try_from(code)?, ptr))
            }
        }

        impl TryFrom<u8> for Codec {
            type Error = Error;

            fn try_from(code: u8) -> Result<Self, Self::Error> {
                Codec::try_from(code as u64)
            }
        }

        impl TryFrom<u16> for Codec {
            type Error = Error;

            fn try_from(code: u16) -> Result<Self, Self::Error> {
                Codec::try_from(code as u64)
            }
        }

        impl TryFrom<u32> for Codec {
            type Error = Error;

            fn try_from(code: u32) -> Result<Self, Self::Error> {
                Codec::try_from(code as u64)
            }
        }

        impl TryFrom<i8> for Codec {
            type Error = Error;

            fn try_from(code: i8) -> Result<Self, Self::Error> {
                Codec::try_from(code as u64)
            }
        }

        impl TryFrom<i16> for Codec {
            type Error = Error;

            fn try_from(code: i16) -> Result<Self, Self::Error> {
                Codec::try_from(code as u64)
            }
        }

        impl TryFrom<i32> for Codec {
            type Error = Error;

            fn try_from(code: i32) -> Result<Self, Self::Error> {
                Codec::try_from(code as u64)
            }
        }

        impl TryFrom<i64> for Codec {
            type Error = Error;

            fn try_from(code: i64) -> Result<Self, Self::Error> {
                Codec::try_from(code as u64)
            }
        }

        impl fmt::Debug for Codec {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{} (0x{:x})", self.as_str(), self.code())
            }
        }

        impl fmt::Display for Codec {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{}", self.as_str())
            }
        }

        impl Null for Codec {
            fn null() -> Self {
                Self::default()
            }

            fn is_null(&self) -> bool {
                *self == Self::null()
            }
        }

        impl Codec {
            /// Get the base code. NOTE: these are NOT varuint encoded
            pub fn code(&self) -> u64 {
                self.clone().into()
            }

            /// Convert a codec to &str
            pub fn as_str(&self) -> &str {
                self.clone().into()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        assert_eq!(Codec::Identity, Codec::default());
    }

    #[test]
    fn test_null() {
        let c1 = Codec::null();
        assert!(c1.is_null());
        let c2 = Codec::default();
        assert_eq!(c1, c2);
        assert!(c2.is_null());
    }

    #[test]
    fn test_to_code() {
        assert_eq!(0xED, Codec::Ed25519Pub.code());
    }

    #[test]
    fn test_from_code() {
        assert_eq!(Codec::Ed25519Pub, Codec::try_from(0xED).unwrap());
    }

    #[test]
    fn test_into_code() {
        assert_eq!(0xED_u64, <Codec as Into<u64>>::into(Codec::Ed25519Pub));
    }

    #[test]
    fn test_to_str() {
        assert_eq!("ed25519-pub", Codec::Ed25519Pub.as_str());
    }

    #[test]
    fn test_from_str() {
        assert_eq!(Codec::Ed25519Pub, Codec::try_from("ed25519-pub").unwrap());
    }

    #[test]
    fn test_encode_into() {
        let v: Vec<u8> = Codec::Ed25519Pub.into();
        assert_eq!(vec![0xED, 0x01], v);
    }

    #[test]
    fn test_debug_format() {
        assert_eq!(
            "ed25519-pub (0xed)".to_string(),
            format!("{:?}", Codec::Ed25519Pub)
        );
    }

    #[test]
    #[should_panic]
    fn test_invalid_value() {
        Codec::try_from(0xDEAD_u64).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_invalid_name() {
        Codec::try_from("move-zig").unwrap();
    }
}

include!("table_gen.rs");
