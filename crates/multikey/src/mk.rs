// SPDX-License-Idnetifier: Apache-2.0
use crate::{
    error::{AttributesError, CipherError, ConversionsError, KdfError},
    views::{bcrypt, bls12381, chacha20, ed25519, mlkem, secp256k1},
    AttrId, AttrView, CipherAttrView, CipherView, ConvView, DataView, Error, FingerprintView,
    KdfAttrView, KdfView, SignView, ThresholdAttrView, ThresholdView, VerifyView, Views,
};
use ml_kem::{EncodedSizeUser, KemCore};
use multibase::Base;
use multicodec::Codec;
use multitrait::{Null, TryDecodeFrom};
use multiutil::{BaseEncoded, CodecInfo, EncodingInfo, Varbytes, VarbytesIter, Varuint};
use ssh_key::{
    private::{EcdsaKeypair, KeypairData},
    public::{EcdsaPublicKey, KeyData},
    EcdsaCurve, PrivateKey, PublicKey,
};
use std::{collections::BTreeMap, fmt, num::NonZeroUsize};
use zeroize::Zeroizing;

/// the list of key codecs supported for key generation
pub const KEY_CODECS: [Codec; 7] = [
    Codec::Bls12381G1Priv,
    Codec::Bls12381G2Priv,
    Codec::Ed25519Priv,
    /*
    Codec::LamportSha3256Priv,
    Codec::LamportSha3384Priv,
    Codec::LamportSha3512Priv,
    Codec::P256Priv,
    Codec::P384Priv,
    Codec::P521Priv,
    */
    Codec::Mlkem512Priv,
    Codec::Mlkem768Priv,
    Codec::Mlkem1024Priv,
    Codec::Secp256K1Priv,
];

/// the list of key share codecs supported
pub const KEY_SHARE_CODECS: [Codec; 4] = [
    Codec::Bls12381G1PubShare,
    Codec::Bls12381G1PrivShare,
    Codec::Bls12381G2PubShare,
    Codec::Bls12381G2PrivShare,
    /*
    Codec::LamportSha3256PrivShare,
    Codec::LamportSha3384PrivShare,
    Codec::LamportSha3512PrivShare,
    */
];

/// the multicodec sigil for multikey
pub const SIGIL: Codec = Codec::Multikey;

/// A base encoded Multikey structure
pub type EncodedMultikey = BaseEncoded<Multikey>;

/// The Multikey attributes type
pub type Attributes = BTreeMap<AttrId, Zeroizing<Vec<u8>>>;

/// The main multikey structure
#[derive(Clone, Default, Eq, PartialEq)]
pub struct Multikey {
    /// key codec
    pub(crate) codec: Codec,
    /// the comment for the key
    pub comment: String,
    /// codec-specific attributes, sorted by key
    pub attributes: Attributes,
}

impl CodecInfo for Multikey {
    /// Return that we are a Multikey object
    fn preferred_codec() -> Codec {
        SIGIL
    }

    /// Return the key coded for the Multikey
    fn codec(&self) -> Codec {
        self.codec
    }
}

impl EncodingInfo for Multikey {
    /// Return the preferred string encoding
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    /// Same
    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl From<Multikey> for Vec<u8> {
    fn from(mk: Multikey) -> Self {
        let mut v = Vec::default();
        // add in the sigil
        v.append(&mut SIGIL.into());
        // add in the key codec
        v.append(&mut mk.codec.into());
        // add in the comment
        v.extend(&mut VarbytesIter::from(mk.comment.as_bytes()));
        // add in the number of codec-specific attributes
        v.append(&mut Varuint(mk.attributes.len()).into());
        // add in the codec-specific attributes
        mk.attributes.iter().for_each(|(id, attr)| {
            v.append(&mut (*id).into());
            v.extend(&mut VarbytesIter::from(attr.as_slice()));
        });
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for Multikey {
    type Error = Error;

    fn try_from(s: &'a [u8]) -> Result<Self, Self::Error> {
        let (mk, _) = Self::try_decode_from(s)?;
        Ok(mk)
    }
}

impl<'a> TryDecodeFrom<'a> for Multikey {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the sigil
        let (sigil, ptr) = Codec::try_decode_from(bytes)?;
        if sigil != SIGIL {
            return Err(Error::MissingSigil);
        }
        // decode the key codec
        let (codec, ptr) = Codec::try_decode_from(ptr)?;
        // decode the comment
        let (comment, ptr) = Varbytes::try_decode_from(ptr)?;
        let comment = String::from_utf8(comment.to_inner())?;
        // decode the number of codec-specific attributes
        let (num_attr, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        // decode the codec-specific values
        let (attributes, ptr) = match *num_attr {
            0 => (Attributes::default(), ptr),
            _ => {
                let mut attributes = Attributes::new();
                let mut p = ptr;
                for _ in 0..*num_attr {
                    let (id, ptr) = AttrId::try_decode_from(p)?;
                    let (attr, ptr) = Varbytes::try_decode_from(ptr)?;
                    if attributes.insert(id, (*attr).clone().into()).is_some() {
                        return Err(Error::DuplicateAttribute(id.code()));
                    }
                    p = ptr;
                }
                (attributes, p)
            }
        };
        Ok((
            Self {
                codec,
                comment,
                attributes,
            },
            ptr,
        ))
    }
}

impl Null for Multikey {
    fn null() -> Self {
        Self::default()
    }

    fn is_null(&self) -> bool {
        *self == Self::null()
    }
}

impl fmt::Debug for Multikey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // get an attributes view on the key
        let attr = self.attr_view().map_err(|_| fmt::Error)?;

        write!(
            f,
            "{:?} - {:?} - Encrypted: {}",
            SIGIL,
            self.codec(),
            if attr.is_encrypted() { "true" } else { "false" }
        )
    }
}

impl Views for Multikey {
    /// Provide a read-only view of the basic attributes in the viewed Multikey
    fn attr_view<'a>(&'a self) -> Result<Box<dyn AttrView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G1PubShare
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub
            | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::try_from(self)?)),
            Codec::Mlkem512Pub
            | Codec::Mlkem512Priv
            | Codec::Mlkem768Pub
            | Codec::Mlkem768Priv
            | Codec::Mlkem1024Pub
            | Codec::Mlkem1024Priv => Ok(Box::new(mlkem::View::try_from(self)?)),
            _ => Err(AttributesError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide a read-only view of the cipher attributes in the viewed Multikey
    fn cipher_attr_view<'a>(&'a self) -> Result<Box<dyn CipherAttrView + 'a>, Error> {
        let codec = if let Some(bytes) = self.attributes.get(&AttrId::CipherCodec) {
            Codec::try_from(bytes.as_slice())?
        } else {
            self.codec
        };
        match codec {
            Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::try_from(self)?)),
            Codec::Mlkem512Pub
            | Codec::Mlkem512Priv
            | Codec::Mlkem768Pub
            | Codec::Mlkem768Priv
            | Codec::Mlkem1024Pub
            | Codec::Mlkem1024Priv => Ok(Box::new(mlkem::View::try_from(self)?)),
            _ => Err(CipherError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide a read-only view to key data in the viewed Multikey
    fn data_view<'a>(&'a self) -> Result<Box<dyn DataView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G1PubShare
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub
            | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::try_from(self)?)),
            Codec::Mlkem512Pub
            | Codec::Mlkem512Priv
            | Codec::Mlkem768Pub
            | Codec::Mlkem768Priv
            | Codec::Mlkem1024Pub
            | Codec::Mlkem1024Priv => Ok(Box::new(mlkem::View::try_from(self)?)),
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide a read-only view of the kdf attributes in the viewed Multikey
    fn kdf_attr_view<'a>(&'a self) -> Result<Box<dyn KdfAttrView + 'a>, Error> {
        let codec = if let Some(bytes) = self.attributes.get(&AttrId::KdfCodec) {
            Codec::try_from(bytes.as_slice())?
        } else {
            self.codec
        };
        match codec {
            Codec::BcryptPbkdf => Ok(Box::new(bcrypt::View::try_from(self)?)),
            _ => Err(KdfError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide a read-only view of the threshold attributes in the viewed Multikey
    fn threshold_attr_view<'a>(&'a self) -> Result<Box<dyn ThresholdAttrView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G1PubShare
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub
            | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(self)?)),
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to do encryption/decryption of the viewed Multikey
    fn cipher_view<'a>(&'a self, cipher: &'a Multikey) -> Result<Box<dyn CipherView + 'a>, Error> {
        match cipher.codec {
            Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::new(self, cipher))),
            Codec::Mlkem512Pub
            | Codec::Mlkem512Priv
            | Codec::Mlkem768Pub
            | Codec::Mlkem768Priv
            | Codec::Mlkem1024Pub
            | Codec::Mlkem1024Priv => Ok(Box::new(mlkem::View::new(self, cipher))),
            _ => Err(CipherError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to do key conversions from the viewe Multikey
    fn conv_view<'a>(&'a self) -> Result<Box<dyn ConvView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G1PubShare
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub
            | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            Codec::Mlkem512Pub
            | Codec::Mlkem512Priv
            | Codec::Mlkem768Pub
            | Codec::Mlkem768Priv
            | Codec::Mlkem1024Pub
            | Codec::Mlkem1024Priv => Ok(Box::new(mlkem::View::try_from(self)?)),
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to do key conversions from the viewe Multikey
    fn fingerprint_view<'a>(&'a self) -> Result<Box<dyn FingerprintView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G1PubShare
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub
            | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::try_from(self)?)),
            Codec::Mlkem512Pub
            | Codec::Mlkem512Priv
            | Codec::Mlkem768Pub
            | Codec::Mlkem768Priv
            | Codec::Mlkem1024Pub
            | Codec::Mlkem1024Priv => Ok(Box::new(mlkem::View::try_from(self)?)),
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to do kdf operations from the viewed Multikey
    fn kdf_view<'a>(&'a self, kdf: &'a Multikey) -> Result<Box<dyn KdfView + 'a>, Error> {
        match kdf.codec {
            Codec::BcryptPbkdf => Ok(Box::new(bcrypt::View::new(self, kdf))),
            _ => Err(KdfError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to sign a message and return a Multisig
    fn sign_view<'a>(&'a self) -> Result<Box<dyn SignView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G1PubShare
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub
            | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to do threshold operations on the Multikey
    fn threshold_view<'a>(&'a self) -> Result<Box<dyn ThresholdView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1Priv | Codec::Bls12381G2Priv => {
                Ok(Box::new(bls12381::View::try_from(self)?))
            }
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to verify a Multisig and optional message
    fn verify_view<'a>(&'a self) -> Result<Box<dyn VerifyView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G1PubShare
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub
            | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }
}

/// Multikey builder constructs private keys only. If you need a public key you
/// must first generate a priate key and then get the public key from that.
#[derive(Clone, Default)]
pub struct Builder {
    codec: Codec,
    comment: Option<String>,
    base_encoding: Option<Base>,
    attributes: Option<Attributes>,
    shares: Option<Vec<Multikey>>,
}

impl Builder {
    /// create a new multikey with the given codec
    pub fn new(codec: Codec) -> Self {
        Builder {
            codec,
            ..Default::default()
        }
    }

    /// new builder from random bytes source
    pub fn new_from_random_bytes(
        codec: Codec,
        rng: &mut impl rand_core_6::CryptoRngCore,
    ) -> Result<Self, Error> {
        let key_bytes = match codec {
            Codec::Ed25519Priv => ed25519_dalek::SigningKey::generate(rng).to_bytes().to_vec(),
            Codec::P256Priv => EcdsaKeypair::random(rng, EcdsaCurve::NistP256)
                .map_err(|e| ConversionsError::Ssh(e.into()))?
                .private_key_bytes()
                .to_vec(),
            Codec::P384Priv => EcdsaKeypair::random(rng, EcdsaCurve::NistP384)
                .map_err(|e| ConversionsError::Ssh(e.into()))?
                .private_key_bytes()
                .to_vec(),
            Codec::P521Priv => EcdsaKeypair::random(rng, EcdsaCurve::NistP521)
                .map_err(|e| ConversionsError::Ssh(e.into()))?
                .private_key_bytes()
                .to_vec(),
            Codec::Secp256K1Priv => k256::SecretKey::random(rng).to_bytes().to_vec(),
            Codec::Bls12381G1Priv => blsful::Bls12381G1::new_secret_key()
                .to_be_bytes()
                .as_slice()
                .to_vec(),
            Codec::Bls12381G2Priv => blsful::Bls12381G2::new_secret_key()
                .to_be_bytes()
                .as_slice()
                .to_vec(),
            Codec::Mlkem512Priv => {
                let (decapsulation_key, _) = ml_kem::MlKem512::generate(rng);
                decapsulation_key.as_bytes().to_vec()
            }
            Codec::Mlkem768Priv => {
                let (decapsulation_key, _) = ml_kem::MlKem768::generate(rng);
                decapsulation_key.as_bytes().to_vec()
            }
            Codec::Mlkem1024Priv => {
                let (decapsulation_key, _) = ml_kem::MlKem1024::generate(rng);
                decapsulation_key.as_bytes().to_vec()
            }
            _ => return Err(ConversionsError::UnsupportedCodec(codec).into()),
        };
        let mut attributes = Attributes::new();
        attributes.insert(AttrId::KeyData, key_bytes.into());
        Ok(Builder {
            codec,
            attributes: Some(attributes),
            ..Default::default()
        })
    }

    /// new builder from ssh_key::PublicKey source
    pub fn new_from_ssh_public_key(sshkey: &PublicKey) -> Result<Self, Error> {
        use ssh_key::Algorithm::*;
        match sshkey.algorithm() {
            Ecdsa { curve } => {
                use EcdsaCurve::*;
                let (key_bytes, codec) = match curve {
                    NistP256 => {
                        if let KeyData::Ecdsa(EcdsaPublicKey::NistP256(point)) = sshkey.key_data() {
                            (point.as_bytes().to_vec(), Codec::P256Pub)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                    NistP384 => {
                        if let KeyData::Ecdsa(EcdsaPublicKey::NistP384(point)) = sshkey.key_data() {
                            (point.as_bytes().to_vec(), Codec::P384Pub)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                    NistP521 => {
                        if let KeyData::Ecdsa(EcdsaPublicKey::NistP521(point)) = sshkey.key_data() {
                            (point.as_bytes().to_vec(), Codec::P521Pub)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                };
                let mut attributes = Attributes::new();
                attributes.insert(AttrId::KeyData, key_bytes.into());
                Ok(Builder {
                    codec,
                    comment: Some(sshkey.comment().to_string()),
                    attributes: Some(attributes),
                    ..Default::default()
                })
            }
            Ed25519 => {
                let key_bytes = match sshkey.key_data() {
                    KeyData::Ed25519(e) => e.0.to_vec(),
                    _ => {
                        return Err(ConversionsError::UnsupportedAlgorithm(
                            sshkey.algorithm().to_string(),
                        )
                        .into())
                    }
                };
                let mut attributes = Attributes::new();
                attributes.insert(AttrId::KeyData, key_bytes.into());
                Ok(Builder {
                    codec: Codec::Ed25519Pub,
                    comment: Some(sshkey.comment().to_string()),
                    attributes: Some(attributes),
                    ..Default::default()
                })
            }
            Other(name) => match name.as_str() {
                mlkem::ALGORITHM_NAME_512
                | mlkem::ALGORITHM_NAME_768
                | mlkem::ALGORITHM_NAME_1024 => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    let codec = match name.as_str() {
                        mlkem::ALGORITHM_NAME_512 => Codec::Mlkem512Pub,
                        mlkem::ALGORITHM_NAME_768 => Codec::Mlkem768Pub,
                        mlkem::ALGORITHM_NAME_1024 => Codec::Mlkem1024Pub,
                        _ => unreachable!(),
                    };
                    Ok(Builder {
                        codec,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                secp256k1::ALGORITHM_NAME => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Secp256K1Pub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G1 => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G1Pub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G1_SHARE => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let key_share = bls12381::KeyShare::try_from(key_bytes.as_ref())?;
                    let identifier: Vec<u8> = Varuint(key_share.0).into();
                    let threshold: Vec<u8> = Varuint::<usize>(key_share.1.into()).into();
                    let limit: Vec<u8> = Varuint::<usize>(key_share.2.into()).into();
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::ShareIdentifier, identifier.into());
                    attributes.insert(AttrId::Threshold, threshold.into());
                    attributes.insert(AttrId::Limit, limit.into());
                    attributes.insert(AttrId::KeyData, key_share.3.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G1PubShare,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G2 => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G2Pub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G2_SHARE => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let key_share = bls12381::KeyShare::try_from(key_bytes.as_ref())?;
                    let identifier: Vec<u8> = Varuint(key_share.0).into();
                    let threshold: Vec<u8> = Varuint::<usize>(key_share.1.into()).into();
                    let limit: Vec<u8> = Varuint::<usize>(key_share.2.into()).into();
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::ShareIdentifier, identifier.into());
                    attributes.insert(AttrId::Threshold, threshold.into());
                    attributes.insert(AttrId::Limit, limit.into());
                    attributes.insert(AttrId::KeyData, key_share.3.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G1PubShare,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                s => Err(ConversionsError::UnsupportedAlgorithm(s.to_string()).into()),
            },
            _ => Err(ConversionsError::UnsupportedAlgorithm(sshkey.algorithm().to_string()).into()),
        }
    }

    /// new builder from ssh_key::PrivateKey source
    pub fn new_from_ssh_private_key(sshkey: &PrivateKey) -> Result<Self, Error> {
        use ssh_key::Algorithm::*;
        match sshkey.algorithm() {
            Ecdsa { curve } => {
                use EcdsaCurve::*;
                let (key_bytes, codec) = match curve {
                    NistP256 => {
                        if let KeypairData::Ecdsa(EcdsaKeypair::NistP256 { private, .. }) =
                            sshkey.key_data()
                        {
                            (private.as_slice().to_vec(), Codec::P256Priv)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                    NistP384 => {
                        if let KeypairData::Ecdsa(EcdsaKeypair::NistP384 { private, .. }) =
                            sshkey.key_data()
                        {
                            (private.as_slice().to_vec(), Codec::P384Priv)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                    NistP521 => {
                        if let KeypairData::Ecdsa(EcdsaKeypair::NistP521 { private, .. }) =
                            sshkey.key_data()
                        {
                            (private.as_slice().to_vec(), Codec::P521Priv)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                };
                let mut attributes = Attributes::new();
                attributes.insert(AttrId::KeyData, key_bytes.into());
                Ok(Builder {
                    codec,
                    comment: Some(sshkey.comment().to_string()),
                    attributes: Some(attributes),
                    ..Default::default()
                })
            }
            Ed25519 => {
                let key_bytes = match sshkey.key_data() {
                    KeypairData::Ed25519(e) => e.private.to_bytes().to_vec(),
                    _ => {
                        return Err(ConversionsError::UnsupportedAlgorithm(
                            sshkey.algorithm().to_string(),
                        )
                        .into())
                    }
                };
                let mut attributes = Attributes::new();
                attributes.insert(AttrId::KeyData, key_bytes.into());
                Ok(Builder {
                    codec: Codec::Ed25519Priv,
                    comment: Some(sshkey.comment().to_string()),
                    attributes: Some(attributes),
                    ..Default::default()
                })
            }
            Other(name) => match name.as_str() {
                mlkem::ALGORITHM_NAME_512
                | mlkem::ALGORITHM_NAME_768
                | mlkem::ALGORITHM_NAME_1024 => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    let codec = match name.as_str() {
                        mlkem::ALGORITHM_NAME_512 => Codec::Mlkem512Priv,
                        mlkem::ALGORITHM_NAME_768 => Codec::Mlkem768Priv,
                        mlkem::ALGORITHM_NAME_1024 => Codec::Mlkem1024Priv,
                        _ => unreachable!(),
                    };
                    Ok(Builder {
                        codec,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                secp256k1::ALGORITHM_NAME => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Secp256K1Priv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G1 => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G1Priv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G1_SHARE => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let key_share = bls12381::KeyShare::try_from(key_bytes.as_ref())?;
                    let identifier: Vec<u8> = Varuint(key_share.0).into();
                    let threshold: Vec<u8> = Varuint::<usize>(key_share.1.into()).into();
                    let limit: Vec<u8> = Varuint::<usize>(key_share.2.into()).into();
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::ShareIdentifier, identifier.into());
                    attributes.insert(AttrId::Threshold, threshold.into());
                    attributes.insert(AttrId::Limit, limit.into());
                    attributes.insert(AttrId::KeyData, key_share.3.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G1PrivShare,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G2 => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G2Priv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G2_SHARE => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let key_share = bls12381::KeyShare::try_from(key_bytes.as_ref())?;
                    let identifier: Vec<u8> = Varuint(key_share.0).into();
                    let threshold: Vec<u8> = Varuint::<usize>(key_share.1.into()).into();
                    let limit: Vec<u8> = Varuint::<usize>(key_share.2.into()).into();
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::ShareIdentifier, identifier.into());
                    attributes.insert(AttrId::Threshold, threshold.into());
                    attributes.insert(AttrId::Limit, limit.into());
                    attributes.insert(AttrId::KeyData, key_share.3.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G2PrivShare,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                s => Err(ConversionsError::UnsupportedAlgorithm(s.to_string()).into()),
            },
            _ => Err(ConversionsError::UnsupportedAlgorithm(sshkey.algorithm().to_string()).into()),
        }
    }

    /// Create a new [Multikey] from a seed.
    ///
    /// Currently only supports [Codec::Ed25519Priv] seeds.
    pub fn new_from_seed(codec: Codec, seed: &[u8]) -> Result<Self, Error> {
        match codec {
            Codec::Ed25519Priv => {
                let keypair =
                    ssh_key::private::Ed25519Keypair::from_seed(seed.try_into().map_err(|_| {
                        ConversionsError::UnsupportedAlgorithm(
                            "Ed25519 seed must be 32 bytes long".to_string(),
                        )
                    })?);
                let private_key = PrivateKey::try_from(KeypairData::Ed25519(keypair))
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                Self::new_from_ssh_private_key(&private_key)
            }
            Codec::Mlkem512Priv | Codec::Mlkem768Priv | Codec::Mlkem1024Priv => {
                if seed.len() != 64 {
                    return Err(ConversionsError::UnsupportedAlgorithm(
                        "Mlkem seeds must be 64 bytes long".to_string(),
                    )
                    .into());
                }
                let (d, z) = seed.split_at(32);
                let d = ml_kem::B32::try_from(d).map_err(|_| {
                    ConversionsError::UnsupportedAlgorithm(
                        "Mlkem seed must be 64 bytes long".to_string(),
                    )
                })?;
                let z = ml_kem::B32::try_from(z).map_err(|_| {
                    ConversionsError::UnsupportedAlgorithm(
                        "Mlkem seed must be 64 bytes long".to_string(),
                    )
                })?;
                let decapsulation_key = match codec {
                    Codec::Mlkem512Priv => {
                        let (dk, _) = ml_kem::MlKem512::generate_deterministic(&d, &z);
                        dk.as_bytes().to_vec()
                    }
                    Codec::Mlkem768Priv => {
                        let (dk, _) = ml_kem::MlKem768::generate_deterministic(&d, &z);
                        dk.as_bytes().to_vec()
                    }
                    Codec::Mlkem1024Priv => {
                        let (dk, _) = ml_kem::MlKem1024::generate_deterministic(&d, &z);
                        dk.as_bytes().to_vec()
                    }
                    _ => unreachable!(),
                };
                let mut attributes = Attributes::new();
                attributes.insert(AttrId::KeyData, decapsulation_key.into());
                Ok(Builder {
                    codec,
                    attributes: Some(attributes),
                    ..Default::default()
                })
            }
            _ => Err(ConversionsError::UnsupportedCodec(codec).into()),
        }
    }

    /// add an encoding
    pub fn with_base_encoding(mut self, base: Base) -> Self {
        self.base_encoding = Some(base);
        self
    }

    /// add a comment
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.comment = Some(comment.to_string());
        self
    }

    fn with_attribute(mut self, attr: AttrId, data: &Vec<u8>) -> Self {
        let mut attributes = self.attributes.unwrap_or_default();
        attributes.insert(attr, data.to_owned().into());
        self.attributes = Some(attributes);
        self
    }

    /// add in the key bytes directly
    pub fn with_key_bytes(self, bytes: &impl AsRef<[u8]>) -> Self {
        self.with_attribute(AttrId::KeyData, &bytes.as_ref().to_vec())
    }

    /// add in the threshold value
    pub fn with_threshold(self, threshold: NonZeroUsize) -> Self {
        self.with_attribute(
            AttrId::Threshold,
            &Varuint::<usize>(threshold.into()).into(),
        )
    }

    /// add in the limit value
    pub fn with_limit(self, limit: NonZeroUsize) -> Self {
        self.with_attribute(AttrId::Limit, &Varuint::<usize>(limit.into()).into())
    }

    /// add in the share identifier value
    pub fn with_identifier(self, identifier: u8) -> Self {
        self.with_attribute(AttrId::ShareIdentifier, &Varuint(identifier).into())
    }

    /// add in the threshold data
    pub fn with_threshold_data(self, tdata: &impl AsRef<[u8]>) -> Self {
        self.with_attribute(AttrId::ThresholdData, &tdata.as_ref().to_vec())
    }

    /// add a key share
    pub fn add_key_share(mut self, share: &Multikey) -> Self {
        let mut shares = self.shares.unwrap_or_default();
        shares.push(share.clone());
        self.shares = Some(shares);
        self
    }

    /// build a base encoded multikey
    pub fn try_build_encoded(self) -> Result<EncodedMultikey, Error> {
        Ok(BaseEncoded::new(
            self.base_encoding
                .unwrap_or_else(Multikey::preferred_encoding),
            self.try_build()?,
        ))
    }

    /// build a key using key bytes
    pub fn try_build(self) -> Result<Multikey, Error> {
        let codec = self.codec;
        let comment = self.comment.unwrap_or_default();
        let attributes = self.attributes.unwrap_or_default();
        let mut mk = Multikey {
            codec,
            comment,
            attributes,
        };
        if let Some(shares) = self.shares {
            for share in &shares {
                mk = {
                    let tv = mk.threshold_view()?;
                    // if ConversionsError::UnsupportedCodec, we can just ignore it
                    tv.add_share(share)?
                };
            }
            Ok(mk)
        } else {
            Ok(mk)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use super::*;
    use crate::{cipher, kdf};
    use multisig::EncodedMultisig;
    use rng::StdRng;
    use ssh_key::private::Ed25519Keypair;
    use test_log::test;
    use tracing::{info, span, Level};

    #[test]
    fn test_random() {
        let _s = span!(Level::INFO, "test_random").entered();
        for codec in KEY_CODECS {
            let mut rng = StdRng::from_os_rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();
            let (vpk, epk) = {
                let conv = mk.conv_view().unwrap();
                let pk = conv.to_public_key().unwrap();
                (Into::<Vec<u8>>::into(pk.clone()), EncodedMultikey::from(pk))
            };
            let sk = mk.data_view().unwrap().secret_bytes().unwrap();
            info!("{codec} key length: {}", sk.len());

            info!("encoded pubkey: {}: {}", codec, epk);
            info!("encoded pubkey v: {}: {}", codec, hex::encode(vpk));
            info!(
                "encoded privkey: {}: {}",
                codec,
                EncodedMultikey::from(mk.clone())
            );
            info!(
                "encoded privkey v: {}: {}",
                codec,
                hex::encode(Into::<Vec<u8>>::into(mk.clone()))
            );
            let _v: Vec<u8> = mk.into();
        }
    }

    #[test]
    fn test_encoded_random() {
        let _s = span!(Level::INFO, "test_encoded_random").entered();
        for codec in KEY_CODECS {
            let mut rng = StdRng::from_os_rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_base_encoding(Base::Base32Lower)
                .with_comment("test key")
                .try_build_encoded()
                .unwrap();
            let s = mk.to_string();
            //println!("encoded privkey: {}: {}", codec, s);
            assert_eq!(mk, EncodedMultikey::try_from(s.as_str()).unwrap());
        }
    }

    #[test]
    fn test_random_public_ssh_key_roundtrip() {
        let _s = span!(Level::INFO, "test_random_public_ssh_key_roundtrip").entered();
        for codec in KEY_CODECS {
            let mut rng = StdRng::from_os_rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();
            let conv = mk.conv_view().unwrap();
            let pk = conv.to_public_key().unwrap();
            let ssh_key = conv.to_ssh_public_key().unwrap();
            let mk2 = Builder::new_from_ssh_public_key(&ssh_key)
                .unwrap()
                .try_build()
                .unwrap();
            assert_eq!(pk, mk2);
        }
    }

    #[test]
    fn test_random_private_ssh_key_roundtrip() {
        let _s = span!(Level::INFO, "test_random_private_ssh_key_roundtrip").entered();
        for codec in KEY_CODECS {
            let mut rng = StdRng::from_os_rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();
            let conv = mk.conv_view().unwrap();
            let ssh_key = conv.to_ssh_private_key().unwrap();
            let mk2 = Builder::new_from_ssh_private_key(&ssh_key)
                .unwrap()
                .try_build()
                .unwrap();
            assert_eq!(mk, mk2);
        }
    }

    #[test]
    fn test_ssh_key_roundtrip() {
        let _s = span!(Level::INFO, "test_ssh_key_roundtrip").entered();
        for codec in KEY_CODECS {
            let mut rng = StdRng::from_os_rng();
            let sk1 = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();
            let cv = sk1.conv_view().unwrap();
            let public_key = cv.to_ssh_public_key().unwrap();
            let private_key = cv.to_ssh_private_key().unwrap();

            let pk1 = cv.to_public_key().unwrap();
            let cv = pk1.conv_view().unwrap();
            assert_eq!(public_key, cv.to_ssh_public_key().unwrap());

            let sk2 = Builder::new_from_ssh_private_key(&private_key)
                .unwrap()
                .try_build()
                .unwrap();
            assert_eq!(sk1, sk2);
            let pk2 = Builder::new_from_ssh_public_key(&public_key)
                .unwrap()
                .try_build()
                .unwrap();
            assert_eq!(pk1, pk2);
        }
    }

    #[test]
    fn test_encryption_roundtrip() {
        let _s = span!(Level::INFO, "test_encryption_roundtrip").entered();
        for codec in KEY_CODECS {
            let mut rng = StdRng::from_os_rng();
            let mk1 = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();

            let attr = mk1.attr_view().unwrap();
            assert!(!attr.is_encrypted());
            assert!(!attr.is_public_key());
            assert!(attr.is_secret_key());
            let kd = mk1.data_view().unwrap();
            assert!(kd.key_bytes().is_ok());
            assert!(kd.secret_bytes().is_ok());

            let mk2 = {
                let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
                    .with_random_salt(bcrypt::SALT_LENGTH, &mut rng)
                    .with_rounds(10)
                    .try_build()
                    .unwrap();
                let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
                    .with_random_nonce(&mut rng)
                    .unwrap()
                    .try_build()
                    .unwrap();
                // get the kdf view on the cipher multikey so we can generate a
                // new cipher multikey with the same parameters and the generated key
                let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
                // derive a key from the passphrase and add it to the cipher multikey
                let ciphermk = kdf
                    .derive_key(b"for great justice, move every zig!")
                    .unwrap();
                // get the cipher view on the unencrypted ed25519 secret key so
                // that we can create a new ed25519 secret key with an encrypted
                // key and the kdf and cipher attributes and data
                let cipher = mk1.cipher_view(&ciphermk).unwrap();
                // encrypt the multikey using the cipher

                cipher.encrypt().unwrap()
            };

            let attr = mk2.attr_view().unwrap();
            assert!(attr.is_encrypted());
            assert!(!attr.is_public_key());
            assert!(attr.is_secret_key());
            let kd = mk2.data_view().unwrap();
            assert!(kd.key_bytes().is_ok());
            assert!(kd.secret_bytes().is_err()); // encrypted key

            let mk3 = {
                let kdfmk = kdf::Builder::default()
                    .try_from_multikey(&mk2)
                    .unwrap()
                    .try_build()
                    .unwrap();
                let ciphermk = cipher::Builder::default()
                    .try_from_multikey(&mk2)
                    .unwrap()
                    .try_build()
                    .unwrap();
                // get the kdf view
                let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
                // derive a key from the passphrase and add it to the cipher multikey
                let ciphermk = kdf
                    .derive_key(b"for great justice, move every zig!")
                    .unwrap();
                // get the cipher view
                let cipher = mk2.cipher_view(&ciphermk).unwrap();
                // decrypt the multikey using the cipher

                cipher.decrypt().unwrap()
            };

            let attr = mk3.attr_view().unwrap();
            assert!(!attr.is_encrypted());
            assert!(!attr.is_public_key());
            assert!(attr.is_secret_key());
            let kd = mk3.data_view().unwrap();
            assert!(kd.key_bytes().is_ok());
            assert!(kd.secret_bytes().is_ok());

            // ensure the round trip worked
            assert_eq!(mk1, mk3);
        }
    }

    #[test]
    fn test_signing_detached_roundtrip() {
        let _s = span!(Level::INFO, "test_signing_detached_roundtrip").entered();
        for codec in KEY_CODECS {
            if [
                Codec::Mlkem512Priv,
                Codec::Mlkem768Priv,
                Codec::Mlkem1024Priv,
            ]
            .contains(&codec)
            {
                continue;
            }
            let mut rng = StdRng::from_os_rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();

            let attr = mk.attr_view().unwrap();
            assert!(!attr.is_encrypted());
            assert!(!attr.is_public_key());
            assert!(attr.is_secret_key());
            let kd = mk.data_view().unwrap();
            assert!(kd.key_bytes().is_ok());
            assert!(kd.secret_bytes().is_ok());
            let conv = mk.conv_view().unwrap();
            let pk = EncodedMultikey::new(Base::Base16Lower, conv.to_public_key().unwrap());
            println!("{} pubkey: {}", codec, pk);

            let msg = b"for great justice, move every zig!";

            let signmk = mk.sign_view().unwrap();
            let signature = if codec == Codec::Bls12381G1Priv || codec == Codec::Bls12381G2Priv {
                signmk.sign(msg.as_slice(), false, Some(2_u8)).unwrap()
            } else {
                signmk.sign(msg.as_slice(), false, None).unwrap()
            };
            let sig = EncodedMultisig::new(Base::Base16Lower, signature.clone());
            info!("codec: {codec}:\npubkey: {}\nsignaure: {}", pk, sig);

            let verifymk = mk.verify_view().unwrap();
            assert!(verifymk.verify(&signature, Some(msg.as_slice())).is_ok());
        }
    }

    #[test]
    fn test_signing_merged_roundtrip() {
        let _s = span!(Level::INFO, "test_signing_merged_roundtrip").entered();
        for codec in KEY_CODECS {
            if [
                Codec::Mlkem512Priv,
                Codec::Mlkem768Priv,
                Codec::Mlkem1024Priv,
            ]
            .contains(&codec)
            {
                continue;
            }
            let mut rng = StdRng::from_os_rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();

            let attr = mk.attr_view().unwrap();
            assert!(!attr.is_encrypted());
            assert!(!attr.is_public_key());
            assert!(attr.is_secret_key());
            let kd = mk.data_view().unwrap();
            assert!(kd.key_bytes().is_ok());
            assert!(kd.secret_bytes().is_ok());

            let msg =
                hex::decode("8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682")
                    .unwrap();

            let signmk = mk.sign_view().unwrap();
            let signature = if codec == Codec::Bls12381G1Priv || codec == Codec::Bls12381G2Priv {
                signmk.sign(&msg, true, Some(2_u8)).unwrap()
            } else {
                signmk.sign(&msg, true, None).unwrap()
            };

            // make sure the message is stored correctly in the signature
            assert_eq!(signature.message, msg);

            let verifymk = mk.verify_view().unwrap();
            assert!(verifymk.verify(&signature, None).is_ok());
        }
    }

    #[test]
    fn test_bls_key_combine() {
        let _s = span!(Level::INFO, "test_bls_key_combine").entered();
        let mut rng = StdRng::from_os_rng();
        let mk1 = Builder::new_from_random_bytes(Codec::Bls12381G1Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();
        assert_eq!("test key".to_string(), mk1.comment);

        let tv = mk1.threshold_view().unwrap();
        let shares = tv
            .split(NonZero::new(3).unwrap(), NonZero::new(4).unwrap())
            .unwrap();
        assert_eq!(4, shares.len());
        for share in &shares {
            assert_eq!("test key".to_string(), share.comment);
        }

        let msg = hex::decode("8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682")
            .unwrap();

        let signmk = shares[0].sign_view().unwrap();
        let signature = signmk.sign(msg.as_slice(), false, Some(2_u8)).unwrap();
        let ms: EncodedMultisig = BaseEncoded::new(Base::Base32Z, signature);
        let s = ms.to_string();
        println!("Bls Sig Share: {}", s);

        let mut builder = Builder::new(Codec::Bls12381G1Priv).with_comment("test key");
        for share in &shares {
            builder = builder.add_key_share(share);
        }
        let mk2 = builder.try_build().unwrap();
        assert_eq!("test key".to_string(), mk2.comment);

        let av = mk2.threshold_attr_view().unwrap();
        assert_eq!(3, usize::from(av.threshold().unwrap()));
        assert_eq!(4, usize::from(av.limit().unwrap()));

        let tv = mk2.threshold_view().unwrap();
        let mk3 = tv.combine().unwrap();
        assert_eq!("test key".to_string(), mk3.comment);

        assert_eq!(mk1, mk3);
    }

    #[test]
    fn test_bls_share_ssh_key_roundtrip() {
        let _s = span!(Level::INFO, "test_bls_share_ssh_key_roundtrip").entered();
        let mut rng = StdRng::from_os_rng();
        let mk = Builder::new_from_random_bytes(Codec::Bls12381G1Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();
        let tv = mk.threshold_view().unwrap();
        let sk1 = {
            tv.split(NonZero::new(3).unwrap(), NonZero::new(4).unwrap())
                .unwrap()[0]
                .clone()
        };

        assert_eq!(Codec::Bls12381G1PrivShare, sk1.codec);
        let cv = sk1.conv_view().unwrap();
        let public_key = cv.to_ssh_public_key().unwrap();
        let private_key = cv.to_ssh_private_key().unwrap();

        let pk1 = cv.to_public_key().unwrap();
        let cv = pk1.conv_view().unwrap();
        assert_eq!(public_key, cv.to_ssh_public_key().unwrap());

        let sk2 = Builder::new_from_ssh_private_key(&private_key)
            .unwrap()
            .try_build()
            .unwrap();
        assert_eq!(sk1, sk2);
        let pk2 = Builder::new_from_ssh_public_key(&public_key)
            .unwrap()
            .try_build()
            .unwrap();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_from_ssh_pubkey() {
        let _s = span!(Level::INFO, "test_from_ssh_pubkey").entered();
        let mut rng = StdRng::from_os_rng();
        let kp = KeypairData::Ed25519(Ed25519Keypair::random(&mut rng));
        let sk = PrivateKey::new(kp, "test key").unwrap();

        // build a multikey from the public key
        let mk = Builder::new_from_ssh_public_key(sk.public_key())
            .unwrap()
            .try_build()
            .unwrap();

        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec, Codec::Ed25519Pub);
        assert_eq!(mk.comment, "test key".to_string());
        assert!(!attr.is_encrypted());
        assert!(attr.is_public_key());
        assert!(!attr.is_secret_key());
        let kd = mk.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_err()); // public key
    }

    #[test]
    fn test_from_ssh_privkey() {
        let _s = span!(Level::INFO, "test_from_ssh_privkey").entered();
        let mut rng = StdRng::from_os_rng();
        let kp = KeypairData::Ed25519(Ed25519Keypair::random(&mut rng));
        let sk = PrivateKey::new(kp, "test key").unwrap();

        let mk = Builder::new_from_ssh_private_key(&sk)
            .unwrap()
            .try_build()
            .unwrap();

        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Priv);
        assert_eq!(mk.comment, "test key".to_string());
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());
    }

    #[test]
    fn test_pub_from_string() {
        let _s = span!(Level::INFO, "test_pub_from_string").entered();
        let s = "fba24ed010874657374206b6579010120f9ddcd5118319cc69e6985ef3f4ee3b6c591d46255e1ae5569c8662111b7d3c2".to_string();
        let mk = EncodedMultikey::try_from(s.as_str()).unwrap();
        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Pub);
        assert_eq!(mk.encoding(), Base::Base16Lower);
        assert_eq!(mk.comment, "test key".to_string());
        assert!(!attr.is_encrypted());
        assert!(attr.is_public_key());
        assert!(!attr.is_secret_key());
        let kd = mk.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_err()); // public key
    }

    #[test]
    fn test_priv_from_string() {
        let _s = span!(Level::INFO, "test_priv_from_string").entered();
        let s = "fba2480260874657374206b657901012064e58adf88f85cbec6a0448a0803f9d28cf9231a7141be413f83cf6aa883cd04".to_string();
        let mk = EncodedMultikey::try_from(s.as_str()).unwrap();
        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Priv);
        assert_eq!(mk.encoding(), Base::Base16Lower);
        assert_eq!(mk.comment, "test key".to_string());
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());
    }

    #[test]
    fn test_pub_from_vec() {
        let _s = span!(Level::INFO, "test_pub_from_vec").entered();
        let b = hex::decode("ba24ed010874657374206b6579010120f9ddcd5118319cc69e6985ef3f4ee3b6c591d46255e1ae5569c8662111b7d3c2").unwrap();
        let mk = Multikey::try_from(b.as_slice()).unwrap();
        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Pub);
        assert_eq!(mk.comment, "test key".to_string());
        assert!(!attr.is_encrypted());
        assert!(attr.is_public_key());
        assert!(!attr.is_secret_key());
        let kd = mk.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_err()); // public key
    }

    #[test]
    fn test_priv_from_vec() {
        let _s = span!(Level::INFO, "test_priv_from_vec").entered();
        let b = hex::decode("ba2480260874657374206b657901012064e58adf88f85cbec6a0448a0803f9d28cf9231a7141be413f83cf6aa883cd04").unwrap();
        let mk = Multikey::try_from(b.as_slice()).unwrap();
        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Priv);
        assert_eq!(mk.comment, "test key".to_string());
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());
    }

    #[test]
    fn test_null() {
        let _s = span!(Level::INFO, "test_null").entered();
        let mk1 = Multikey::null();
        assert!(mk1.is_null());
        let mk2 = Multikey::default();
        assert_eq!(mk1, mk2);
        assert!(mk2.is_null());
    }

    #[test]
    fn test_from_seed() {
        let _s = span!(Level::INFO, "test_from_seed").entered();
        let seed = hex::decode("f9ddcd5118319cc69e6985ef3f4ee3b6c591d46255e1ae5569c8662111b7d3c2")
            .unwrap();
        let mk = Builder::new_from_seed(Codec::Ed25519Priv, seed.as_slice())
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();
        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Priv);
        assert_eq!(mk.comment, "test key".to_string());
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());
    }
}
