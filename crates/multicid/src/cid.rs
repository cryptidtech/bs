// SPDX-License-Idnetifier: Apache-2.0
use crate::{error::CidError, Error};
use core::fmt;
use multibase::Base;
use multicodec::Codec;
use multihash::Multihash;
use multitrait::{Null, TryDecodeFrom};
use multiutil::{Base58Encoder, BaseEncoded, CodecInfo, DetectedEncoder, EncodingInfo};

/// the multicodec sigil for Cid
pub const SIGIL: Codec = Codec::Cidv1;

/// a bare base58 encoded Cid
pub type LegacyEncodedCid = BaseEncoded<Cid, Base58Encoder>;

/// a multibase encoded Cid that detects encoding while decoding. this allows transparent support
/// for Base58Btc encoded v0 Cid's as well as multibase encoded v1 Cid's
pub type EncodedCid = BaseEncoded<Cid, DetectedEncoder>;

/// implementation of cid
#[derive(Clone, Eq, Ord, PartialOrd, PartialEq)]
pub struct Cid {
    /// the version of the Cid
    pub(crate) codec: Codec,
    /// target encoding codec
    pub target_codec: Codec,
    /// multihash of the target
    pub hash: Multihash,
}

impl Default for Cid {
    fn default() -> Self {
        Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(&Multihash::default())
            .try_build()
            .unwrap()
    }
}

impl CodecInfo for Cid {
    /// Return that we are a Cid object
    fn preferred_codec() -> Codec {
        SIGIL
    }

    /// Return the codec for this object
    fn codec(&self) -> Codec {
        self.codec
    }
}

impl EncodingInfo for Cid {
    fn preferred_encoding() -> Base {
        Base::Base58Btc
    }

    fn encoding(&self) -> Base {
        if self.codec() == Codec::Identity {
            // v0 Cids like Base58Btc
            Self::preferred_encoding()
        } else {
            // all others like Base32Lower
            Base::Base32Lower
        }
    }
}

impl From<Cid> for Vec<u8> {
    fn from(cid: Cid) -> Self {
        let mut v = Vec::default();
        // if we're not a v0 Cid, add in the version and the encoding codec
        if cid.codec() != Codec::Identity {
            // add in the Cid codec
            v.append(&mut cid.codec.into());
            // add in the target encoding codec
            v.append(&mut cid.target_codec.into());
        }
        // add in the multihash data
        v.append(&mut cid.hash.into());
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for Cid {
    type Error = Error;

    fn try_from(s: &'a [u8]) -> Result<Self, Self::Error> {
        let (mh, _) = Self::try_decode_from(s)?;
        Ok(mh)
    }
}

impl<'a> TryDecodeFrom<'a> for Cid {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the codec at the start
        let (codec, ptr) = Codec::try_decode_from(bytes)?;
        let (codec, target_codec, hash, ptr) = match codec {
            // the codec is a modern Cid codec
            Codec::Cidv1 | Codec::Cidv2 | Codec::Cidv3 => {
                // decode the target encoding codec
                let (target_codec, ptr) = Codec::try_decode_from(ptr)?;

                // decode the multihash
                let (hash, ptr) = Multihash::try_decode_from(ptr)?;

                (codec, target_codec, hash, ptr)
            }
            _ => {
                // everything else we assume is just a multihash codec
                let (hash, ptr) = Multihash::try_decode_from(bytes)?;

                (Codec::Identity, Codec::DagPb, hash, ptr)
            }
        };

        Ok((
            Self {
                codec,
                target_codec,
                hash,
            },
            ptr,
        ))
    }
}

impl Null for Cid {
    fn null() -> Self {
        Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::Identity)
            .with_hash(&Multihash::null())
            .try_build()
            .unwrap()
    }

    fn is_null(&self) -> bool {
        *self == Self::null()
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.codec() != Codec::Identity {
            // we have a v1 or later Cid
            write!(
                f,
                "{:?} - {:?} - {:?}",
                self.codec, self.target_codec, self.hash
            )
        } else {
            write!(f, "cidv0 - {:?} - {:?}", Codec::DagPb, self.hash)
        }
    }
}

/// Hash builder that takes the codec and the data and produces a Multihash
#[derive(Clone, Debug, Default)]
pub struct Builder {
    codec: Option<Codec>,
    target_codec: Option<Codec>,
    hash: Option<Multihash>,
    base_encoding: Option<Base>,
}

impl Builder {
    /// create a cid with the given codec (e.g. Cidv1, etc)
    /// use Builder::default() to get a v0 CID (see the tests below)
    pub fn new(codec: Codec) -> Self {
        Builder {
            codec: Some(codec),
            ..Default::default()
        }
    }

    /// set the target encoding codec
    pub fn with_target_codec(mut self, codec: Codec) -> Self {
        self.target_codec = Some(codec);
        self
    }

    /// set the mulithas
    pub fn with_hash(mut self, hash: &Multihash) -> Self {
        self.hash = Some(hash.clone());
        self
    }

    /// set the base encoding codec
    pub fn with_base_encoding(mut self, base: Base) -> Self {
        self.base_encoding = Some(base);
        self
    }

    /// build a base encoded cid
    pub fn try_build_legacy_encoded(&self) -> Result<LegacyEncodedCid, Error> {
        if self.codec.is_some() {
            return Err(CidError::ModernCid.into());
        }
        Ok(LegacyEncodedCid::new(
            Cid::preferred_encoding(),
            self.try_build()?,
        ))
    }

    /// build a base encoded cid
    pub fn try_build_encoded(&self) -> Result<EncodedCid, Error> {
        if self.codec.is_none() {
            return Err(CidError::LegacyCid.into());
        }
        Ok(EncodedCid::new(
            self.base_encoding
                .unwrap_or_else(Cid::preferred_encoding),
            self.try_build()?,
        ))
    }

    /// build the cid
    pub fn try_build(&self) -> Result<Cid, Error> {
        if let Some(codec) = self.codec {
            // build a v1 or later Cid
            Ok(Cid {
                codec,
                target_codec: self.target_codec.ok_or(CidError::MissingTargetCodec)?,
                hash: self.hash.clone().ok_or(CidError::MissingHash)?,
            })
        } else {
            // build a v0 Cid
            Ok(Cid {
                codec: Codec::Identity,
                target_codec: self.target_codec.unwrap_or(Codec::DagPb),
                hash: self.hash.clone().ok_or(CidError::MissingHash)?,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash::mh;

    #[test]
    fn test_default() {
        let v1 = Cid::default();
        assert_eq!(Codec::Cidv1, v1.codec());
        assert_eq!(Codec::DagCbor, v1.target_codec);
        assert_eq!(Codec::Identity, v1.hash.codec());
    }

    #[test]
    fn test_v0() {
        let v0 = Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        assert_eq!(Codec::Identity, v0.codec());
        assert_eq!(Codec::DagPb, v0.target_codec);
        assert_eq!(Codec::Sha2256, v0.hash.codec());
    }

    #[test]
    fn test_unknown_decode() {
        // this does not assume it is a legacy v0 encoded CID
        let v0_1 = EncodedCid::try_from("Qmdb16CztyugMSs5anEPrJ6bLeo39bTGcM13zNPqjqUidT").unwrap();
        assert_eq!(Codec::Identity, v0_1.codec());
        assert_eq!(Codec::DagPb, v0_1.target_codec);
        assert_eq!(Codec::Sha2256, v0_1.hash.codec());

        // this does not assume a multibase encoded CID
        let v0_2 = EncodedCid::try_from("bafybeihcrr5owouhnms63areolshu2lp4jjbjqlhf4exegk7tnso5ja6py").unwrap();
        assert_eq!(Codec::Cidv1, v0_2.codec());
        assert_eq!(Codec::DagPb, v0_2.target_codec);
        assert_eq!(Codec::Sha2256, v0_2.hash.codec());

        let v0_3 = EncodedCid::try_from("f01701220e28c7aeb3a876b25ed822472e47a696fe25214c1672f0972195f9b64eea41e7e").unwrap();
        assert_eq!(Codec::Cidv1, v0_3.codec());
        assert_eq!(Codec::DagPb, v0_3.target_codec);
        assert_eq!(Codec::Sha2256, v0_3.hash.codec());

        let v0_4 = EncodedCid::try_from("uAXASIOKMeus6h2sl7YIkcuR6aW_iUhTBZy8Jchlfm2TupB5-").unwrap();
        assert_eq!(Codec::Cidv1, v0_4.codec());
        assert_eq!(Codec::DagPb, v0_4.target_codec);
        assert_eq!(Codec::Sha2256, v0_4.hash.codec());

        let v0_5 = EncodedCid::try_from("0000000010111000000010010001000001110001010001100011110101110101100111010100001110110101100100101111011011000001000100100011100101110010001111010011010010110111111100010010100100001010011000001011001110010111100001001011100100001100101011111100110110110010011101110101001000001111001111110").unwrap();
        assert_eq!(Codec::Cidv1, v0_5.codec());
        assert_eq!(Codec::DagPb, v0_5.target_codec);
        assert_eq!(Codec::Sha2256, v0_5.hash.codec());

        assert_eq!(v0_1.hash, v0_2.hash);
        assert_eq!(v0_1.hash, v0_3.hash);
        assert_eq!(v0_1.hash, v0_4.hash);
        assert_eq!(v0_1.hash, v0_5.hash);
    }

    #[test]
    fn test_v0_binary_roundtrip() {
        let v0 = Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();
        let v: Vec<u8> = v0.clone().into();
        assert_eq!(v0, Cid::try_from(v.as_ref()).unwrap());
    }

    #[test]
    fn test_v0_encoded_roundtrip() {
        let v0 = Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build_legacy_encoded()
            .unwrap();
        let s = v0.to_string();
        println!("({}) {}", s.len(), s);
        assert_eq!(v0, LegacyEncodedCid::try_from(s.as_str()).unwrap());
    }

    #[test]
    fn test_v1() {
        let v1 = Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        assert_eq!(Codec::Cidv1, v1.codec());
        assert_eq!(Codec::DagCbor, v1.target_codec);
        assert_eq!(Codec::Sha3512, v1.hash.codec());
    }

    #[test]
    fn test_v1_binary_roundtrip() {
        let v1 = Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();
        let v: Vec<u8> = v1.clone().into();
        assert_eq!(v1, Cid::try_from(v.as_ref()).unwrap());
    }

    #[test]
    fn test_v1_encoded_roundtrip() {
        let v1 = Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_base_encoding(Base::Base32Lower)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build_encoded()
            .unwrap();
        let s = v1.to_string();
        println!("({}) {}", s.len(), s);
        assert_eq!(v1, EncodedCid::try_from(s.as_str()).unwrap());
    }

    #[test]
    fn test_null() {
        let cid1 = Cid::null();
        assert!(cid1.is_null());
        let cid2 = Cid::default();
        assert!(cid1 != cid2);
        assert!(!cid2.is_null());
    }
}
