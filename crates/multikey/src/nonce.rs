// SPDX-License-Idnetifier: Apache-2.0
use crate::{error::NonceError, Error};
use core::fmt;
use multibase::Base;
use multicodec::Codec;
use multitrait::{Null, TryDecodeFrom};
use multiutil::{BaseEncoded, CodecInfo, EncodingInfo, Varbytes};

/// the Nonce multicodec sigil
pub const SIGIL: Codec = Codec::Nonce;

/// a multibase encoded Nonce
pub type EncodedNonce = BaseEncoded<Nonce>;

/// a multicodec Nonce type
#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Nonce {
    /// the random nonce bytes
    pub(crate) nonce: Vec<u8>,
}

impl Nonce {
    /// return the size of the nonce in bytes
    pub fn len(&self) -> usize {
        self.nonce.len()
    }

    /// check for len == 0
    pub fn is_empty(&self) -> bool {
        self.nonce.is_empty()
    }
}

impl CodecInfo for Nonce {
    /// Return that we are a Nonce object
    fn preferred_codec() -> Codec {
        SIGIL
    }

    /// Return the codec for this object
    fn codec(&self) -> Codec {
        Self::preferred_codec()
    }
}

impl EncodingInfo for Nonce {
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        self.nonce.as_ref()
    }
}

impl From<Nonce> for Vec<u8> {
    fn from(val: Nonce) -> Self {
        let mut v = Vec::default();
        // add the sigil
        v.append(&mut SIGIL.into());
        // add the nonce bytes
        v.append(&mut Varbytes(val.nonce.clone()).into());
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for Nonce {
    type Error = Error;

    fn try_from(s: &'a [u8]) -> Result<Self, Self::Error> {
        let (mh, _) = Self::try_decode_from(s)?;
        Ok(mh)
    }
}

impl<'a> TryDecodeFrom<'a> for Nonce {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the sigil
        let (sigil, ptr) = Codec::try_decode_from(bytes)?;
        if sigil != SIGIL {
            return Err(NonceError::MissingSigil.into());
        }
        // decode the none
        let (nonce, ptr) = Varbytes::try_decode_from(ptr)?;
        Ok((
            Self {
                nonce: nonce.to_inner(),
            },
            ptr,
        ))
    }
}

impl Null for Nonce {
    fn null() -> Self {
        Self::default()
    }

    fn is_null(&self) -> bool {
        *self == Self::null()
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} - {}", SIGIL, hex::encode(&self.nonce))
    }
}

/// Hash builder that takes the codec and the data and produces a Multihash
#[derive(Clone, Debug, Default)]
pub struct Builder {
    bytes: Vec<u8>,
    base_encoding: Option<Base>,
}

impl Builder {
    /// build from random source
    pub fn new_from_random_bytes(size: usize, rng: &mut impl rand_core_6::CryptoRngCore) -> Self {
        let mut bytes = vec![0; size];
        bytes.resize(size, 0u8);
        rng.fill_bytes(bytes.as_mut());
        Self {
            bytes,
            ..Default::default()
        }
    }

    /// build from existing bytes
    pub fn new_from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            ..Default::default()
        }
    }

    /// set the base encoding codec
    pub fn with_base_encoding(mut self, base: Base) -> Self {
        self.base_encoding = Some(base);
        self
    }

    /// build a base encoded vlad
    pub fn try_build_encoded(&self) -> Result<EncodedNonce, Error> {
        Ok(EncodedNonce::new(
            self.base_encoding.unwrap_or_else(Nonce::preferred_encoding),
            self.try_build()?,
        ))
    }

    /// build the vlad
    pub fn try_build(&self) -> Result<Nonce, Error> {
        Ok(Nonce {
            nonce: self.bytes.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mk, Views};
    use rng::StdRng;

    #[test]
    fn test_random() {
        let mut rng = StdRng::from_os_rng();
        let n = Builder::new_from_random_bytes(32, &mut rng)
            .try_build()
            .unwrap();

        assert_eq!(Codec::Nonce, n.codec());
        assert_eq!(32, n.len());
    }

    #[test]
    fn test_binary_roundtrip() {
        let mut rng = StdRng::from_os_rng();
        let n = Builder::new_from_random_bytes(32, &mut rng)
            .try_build()
            .unwrap();
        let v: Vec<u8> = n.clone().into();
        assert_eq!(n, Nonce::try_from(v.as_ref()).unwrap());
    }

    #[test]
    fn test_encoded_roundtrip() {
        let mut rng = StdRng::from_os_rng();
        let n = Builder::new_from_random_bytes(32, &mut rng)
            .try_build_encoded()
            .unwrap();
        let s = n.to_string();
        println!("({}) {}", s.len(), s);
        let s = n.to_string();
        assert_eq!(n, EncodedNonce::try_from(s.as_str()).unwrap());
    }

    #[test]
    fn test_nonce_multisig_roundtrip() {
        let mut rng = StdRng::from_os_rng();
        let mk = mk::Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();

        let msg = hex::decode("8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682")
            .unwrap();

        let signmk = mk.sign_view().unwrap();
        let signature = signmk.sign(msg.as_slice(), false, None).unwrap();

        let s: Vec<u8> = signature.into();
        let n = Builder::new_from_bytes(&s).try_build_encoded().unwrap();
        //println!("{}", n);
        let s = n.to_string();
        assert_eq!(n, EncodedNonce::try_from(s.as_str()).unwrap());
    }

    #[test]
    fn test_null() {
        let n1 = Nonce::null();
        assert!(n1.is_null());
        let n2 = Nonce::default();
        assert_eq!(n1, n2);
        assert!(n2.is_null());
    }
}
