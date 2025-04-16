// SPDX-License-Idnetifier: Apache-2.0
use crate::Error;
use core::fmt;
use digest::{Digest, DynDigest};
use multibase::Base;
use multicodec::Codec;
use multitrait::{Null, TryDecodeFrom};
use multiutil::{BaseEncoded, CodecInfo, DetectedEncoder, EncodingInfo, Varbytes};
use typenum::consts::*;

/// the hash codecs currently supported
pub const HASH_CODECS: [Codec; 23] = [
    Codec::Blake2B224,
    Codec::Blake2B256,
    Codec::Blake2B384,
    Codec::Blake2B512,
    Codec::Blake2S224,
    Codec::Blake2S256,
    Codec::Blake3,
    Codec::Md5,
    Codec::Ripemd128,
    Codec::Ripemd160,
    Codec::Ripemd256,
    Codec::Ripemd320,
    Codec::Sha1,
    Codec::Sha2224,
    Codec::Sha2256,
    Codec::Sha2384,
    Codec::Sha2512,
    Codec::Sha2512224,
    Codec::Sha2512256,
    Codec::Sha3224,
    Codec::Sha3256,
    Codec::Sha3384,
    Codec::Sha3512];

/// the safe hash codecs current supported
pub const SAFE_HASH_CODECS: [Codec; 8] = [
    Codec::Blake2B256,
    Codec::Blake2B384,
    Codec::Blake2B512,
    Codec::Blake2S256,
    Codec::Blake3,
    Codec::Sha3256,
    Codec::Sha3384,
    Codec::Sha3512];

/// the multicodec sigil for multihash
pub const SIGIL: Codec = Codec::Multihash;

/// a base encoded multihash
pub type EncodedMultihash = BaseEncoded<Multihash, DetectedEncoder>;

/// inner implementation of the multihash
#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Multihash {
    /// hash codec
    pub(crate) codec: Codec,

    /// hash value
    pub(crate) hash: Vec<u8>,
}

impl CodecInfo for Multihash {
    /// Return that we are a Multihash object
    fn preferred_codec() -> Codec {
        SIGIL
    }

    /// Return the hashing codec for the multihash
    fn codec(&self) -> Codec {
        self.codec
    }
}

impl EncodingInfo for Multihash {
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl From<Multihash> for Vec<u8> {
    fn from(mh: Multihash) -> Vec<u8> {
        let mut v = Vec::default();
        // add in the hash codec
        v.append(&mut mh.codec.into());
        // add in the hash data
        v.append(&mut Varbytes(mh.hash).into());
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for Multihash {
    type Error = Error;

    fn try_from(s: &'a [u8]) -> Result<Self, Self::Error> {
        let (mh, _) = Self::try_decode_from(s)?;
        Ok(mh)
    }
}

impl<'a> TryDecodeFrom<'a> for Multihash {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the hashing codec
        let (codec, ptr) = Codec::try_decode_from(bytes)?;
        // decode the hash bytes
        let (hash, ptr) = Varbytes::try_decode_from(ptr)?;
        // pull the inner Vec<u8> out of Varbytes
        let hash = hash.to_inner();
        Ok((Self { codec, hash }, ptr))
    }
}

/// Exposes direct access to the hash data
impl AsRef<[u8]> for Multihash {
    fn as_ref(&self) -> &[u8] {
        self.hash.as_ref()
    }
}

/// Multihashes can have a null value
impl Null for Multihash {
    fn null() -> Self {
        Multihash::default()
    }

    fn is_null(&self) -> bool {
        *self == Multihash::default()
    }
}

impl fmt::Debug for Multihash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} - {:?} - {}",
            SIGIL,
            self.codec(),
            hex::encode(&self.hash)
        )
    }
}

/// Hash builder that takes the codec and the data and produces a Multihash
#[derive(Clone, Debug, Default)]
pub struct Builder {
    codec: Codec,
    hash: Option<Vec<u8>>,
    base_encoding: Option<Base>,
}

impl Builder {
    /// create a hash with the given codec
    pub fn new(codec: Codec) -> Self {
        Builder {
            codec,
            ..Default::default()
        }
    }

    /// create a new builder from a hash
    pub fn new_from_bytes(codec: Codec, bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        let mut hasher: Box<dyn DynDigest> = match codec {
            Codec::Blake2B224 => Box::new(blake2::Blake2b::<U28>::new()),
            Codec::Blake2B256 => Box::new(blake2::Blake2b::<U32>::new()),
            Codec::Blake2B384 => Box::new(blake2::Blake2b::<U48>::new()),
            Codec::Blake2B512 => Box::new(blake2::Blake2b::<U64>::new()),
            Codec::Blake2S224 => Box::new(blake2::Blake2s::<U28>::new()),
            Codec::Blake2S256 => Box::new(blake2::Blake2s::<U32>::new()),
            Codec::Blake3 => Box::new(blake3::Hasher::new()),
            Codec::Md5 => Box::new(md5::Md5::new()),
            Codec::Ripemd128 => Box::new(ripemd::Ripemd128::new()),
            Codec::Ripemd160 => Box::new(ripemd::Ripemd160::new()),
            Codec::Ripemd256 => Box::new(ripemd::Ripemd256::new()),
            Codec::Ripemd320 => Box::new(ripemd::Ripemd320::new()),
            Codec::Sha1 => Box::new(sha1::Sha1::new()),
            Codec::Sha2224 => Box::new(sha2::Sha224::new()),
            Codec::Sha2256 => Box::new(sha2::Sha256::new()),
            Codec::Sha2384 => Box::new(sha2::Sha384::new()),
            Codec::Sha2512 => Box::new(sha2::Sha512::new()),
            Codec::Sha2512224 => Box::new(sha2::Sha512_224::new()),
            Codec::Sha2512256 => Box::new(sha2::Sha512_256::new()),
            Codec::Sha3224 => Box::new(sha3::Sha3_224::new()),
            Codec::Sha3256 => Box::new(sha3::Sha3_256::new()),
            Codec::Sha3384 => Box::new(sha3::Sha3_384::new()),
            Codec::Sha3512 => Box::new(sha3::Sha3_512::new()),
            _ => return Err(Error::UnsupportedHash(codec)),
        };

        // hash the data
        hasher.update(bytes.as_ref());
        let hash = hasher.finalize().to_vec();
        Ok(Self {
            codec,
            hash: Some(hash),
            base_encoding: None,
        })
    }

    /// set the hash data
    pub fn with_hash(mut self, hash: impl Into<Vec<u8>>) -> Self {
        self.hash = Some(hash.into());
        self
    }

    /// set the base encoding codec
    pub fn with_base_encoding(mut self, base: Base) -> Self {
        self.base_encoding = Some(base);
        self
    }

    /// build a base encoded multihash
    pub fn try_build_encoded(&self) -> Result<EncodedMultihash, Error> {
        Ok(BaseEncoded::new(
            self.base_encoding
                .unwrap_or_else(Multihash::preferred_encoding),
            self.try_build()?,
        ))
    }

    /// build the multihash by hashing the provided data
    pub fn try_build(&self) -> Result<Multihash, Error> {
        Ok(Multihash {
            codec: self.codec,
            hash: self.hash.clone().ok_or(Error::MissingHash)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matrix() {
        let hashers = vec![
            Codec::Blake2B224,
            Codec::Blake2B256,
            Codec::Blake2B384,
            Codec::Blake2B512,
            Codec::Blake2S224,
            Codec::Blake2S256,
            Codec::Blake3,
            Codec::Md5,
            Codec::Ripemd128,
            Codec::Ripemd160,
            Codec::Ripemd256,
            Codec::Ripemd320,
            Codec::Sha1,
            Codec::Sha2224,
            Codec::Sha2256,
            Codec::Sha2384,
            Codec::Sha2512,
            Codec::Sha2512224,
            Codec::Sha2512256,
            Codec::Sha3224,
            Codec::Sha3256,
            Codec::Sha3384,
            Codec::Sha3512,
        ];

        let bases = vec![
            Base::Base2,
            Base::Base8,
            Base::Base10,
            Base::Base16Lower,
            Base::Base16Upper,
            Base::Base32Lower,
            Base::Base32Upper,
            Base::Base32PadLower,
            Base::Base32PadUpper,
            Base::Base32HexLower,
            Base::Base32HexUpper,
            Base::Base32HexPadLower,
            Base::Base32HexPadUpper,
            Base::Base32Z,
            Base::Base36Lower,
            Base::Base36Upper,
            Base::Base58Flickr,
            Base::Base58Btc,
            Base::Base64,
            Base::Base64Pad,
            Base::Base64Url,
            Base::Base64UrlPad,
        ];

        for h in &hashers {
            for b in &bases {
                let mh1 = Builder::new_from_bytes(*h, b"for great justice, move every zig!")
                    .unwrap()
                    .with_base_encoding(*b)
                    .try_build_encoded()
                    .unwrap();
                //println!("{:?}", mh1);
                let s = mh1.to_string();
                assert_eq!(mh1, EncodedMultihash::try_from(s.as_str()).unwrap());
            }
        }
    }

    #[test]
    fn test_binary_roundtrip() {
        let mh1 = Builder::new_from_bytes(Codec::Sha3384, b"for great justice, move every zig!")
            .unwrap()
            .try_build()
            .unwrap();
        let v: Vec<u8> = mh1.clone().into();
        let mh2 = Multihash::try_from(v.as_ref()).unwrap();
        assert_eq!(mh1, mh2);
    }

    #[test]
    fn test_encoded() {
        let mh = Builder::new_from_bytes(Codec::Sha3256, b"for great justice, move every zig!")
            .unwrap()
            .with_base_encoding(Base::Base58Btc)
            .try_build_encoded()
            .unwrap();
        let s = mh.to_string();
        println!("{:?}", mh);
        println!("{s}");
        assert_eq!(mh, EncodedMultihash::try_from(s.as_str()).unwrap());
    }

    #[test]
    fn test_matching() {
        let mh1 = Builder::new_from_bytes(Codec::Sha3256, b"for great justice, move every zig!")
            .unwrap()
            .try_build()
            .unwrap();
        let mh2 = Multihash::try_from(hex::decode("16206b761d3b2e7675e088e337a82207b55711d3957efdb877a3d261b0ca2c38e201").unwrap().as_ref()).unwrap();
        assert_eq!(mh1, mh2);
    }

    #[test]
    fn test_null() {
        let mh1 = Multihash::null();
        assert!(mh1.is_null());
        let mh2 = Multihash::default();
        assert_eq!(mh1, mh2);
        assert!(mh2.is_null());
    }

    #[test]
    fn test_multihash_sha1() {
        // test cases from: https://github.com/multiformats/multihash?tab=readme-ov-file#example
        let bases = vec![
            (Base::Base16Lower, "f111488c2f11fb2ce392acb5b2986e640211c4690073e"),
            (Base::Base32Upper, "BCEKIRQXRD6ZM4OJKZNNSTBXGIAQRYRUQA47A"),
            (Base::Base58Btc, "z5dsgvJGnvAfiR3K6HCBc4hcokSfmjj"),
            (Base::Base64, "mERSIwvEfss45KstbKYbmQCEcRpAHPg"),
        ];

        for (b, h) in bases {
            let mh = Builder::new_from_bytes(Codec::Sha1, b"multihash")
                .unwrap()
                .with_base_encoding(b)
                .try_build_encoded()
                .unwrap();
            let s = mh.to_string();
            assert_eq!(h, s.as_str());
        }
    }

    #[test]
    fn test_multihash_sha2_256() {
        // test cases from: https://github.com/multiformats/multihash?tab=readme-ov-file#example
        let bases = vec![
            (Base::Base16Lower, "f12209cbc07c3f991725836a3aa2a581ca2029198aa420b9d99bc0e131d9f3e2cbe47"),
            (Base::Base32Upper, "BCIQJZPAHYP4ZC4SYG2R2UKSYDSRAFEMYVJBAXHMZXQHBGHM7HYWL4RY"),
            (Base::Base58Btc, "zQmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk"),
            (Base::Base64, "mEiCcvAfD+ZFyWDajqipYHKICkZiqQgudmbwOEx2fPiy+Rw"),
        ];

        for (b, h) in bases {
            let mh = Builder::new_from_bytes(Codec::Sha2256, b"multihash")
                .unwrap()
                .with_base_encoding(b)
                .try_build_encoded()
                .unwrap();
            let s = mh.to_string();
            assert_eq!(h, s.as_str());
        }
    }

}
