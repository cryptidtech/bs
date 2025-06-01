// SPDX-License-Identifier: Apache-2.0
use crate::{
    error::{
        AttributesError, CipherError, ConversionsError, KdfError, SignError, ThresholdError,
        VerifyError,
    },
    AttrId, AttrView, Builder, CipherAttrView, ConvView, DataView, Error, FingerprintView,
    KdfAttrView, Multikey, SignView, ThresholdAttrView, ThresholdView, VerifyView, Views,
};
use blsful::{
    inner_types::{G1Projective, G2Projective},
    vsss_rs::Share,
    Bls12381G1Impl, Bls12381G2Impl, PublicKey, PublicKeyShare, SecretKey, SecretKeyShare,
    Signature, SignatureSchemes, SignatureShare, SECRET_KEY_BYTES,
};
use elliptic_curve::group::GroupEncoding;
use multicodec::Codec;
use multihash::{mh, Multihash};
use multisig::{ms, views::bls12381::SchemeTypeId, Multisig, Views as SigViews};
use multitrait::TryDecodeFrom;
use multiutil::{Varbytes, Varuint};
use ssh_encoding::{Decode, Encode};
use std::{
    array::TryFromSliceError,
    collections::BTreeMap,
    num::{NonZero, NonZeroUsize},
};
use zeroize::Zeroizing;

/// the RFC 4251 algorithm name for SSH compatibility
pub const ALGORITHM_NAME_G1: &str = "bls12_381-g1@multikey";
pub const ALGORITHM_NAME_G1_SHARE: &str = "bls12_381-g1-share@multikey";
pub const ALGORITHM_NAME_G2: &str = "bls12_381-g2@multikey";
pub const ALGORITHM_NAME_G2_SHARE: &str = "bls12_381-g2-share@multikey";

// number of bytes in a G1 and G2 public key
pub const G1_PUBLIC_KEY_BYTES: usize = 48;
pub const G2_PUBLIC_KEY_BYTES: usize = 96;

/// tuple of the key share data with threshold attributes
// TODO: this should be a struct with the share identifier, threshold, limit, and key bytes
#[derive(Clone)]
pub struct KeyShare(
    /// identifier
    pub u8,
    /// threshold,
    pub NonZeroUsize,
    /// limit
    pub NonZeroUsize,
    /// key bytes
    pub Vec<u8>,
);

impl From<KeyShare> for Vec<u8> {
    fn from(val: KeyShare) -> Self {
        let mut v = Vec::default();
        // add in the share identifier
        v.append(&mut Varuint(val.0).into());
        // add in the threshold
        v.append(&mut Varuint::<usize>(val.1.into()).into());
        // add in the limit
        v.append(&mut Varuint::<usize>(val.2.into()).into());
        // add in the key share data
        v.append(&mut Varbytes(val.3.clone()).into());
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for KeyShare {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (share, _) = Self::try_decode_from(bytes)?;
        Ok(share)
    }
}

impl<'a> TryDecodeFrom<'a> for KeyShare {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // try to decode the identifier
        let (id, ptr) = Varuint::<u8>::try_decode_from(bytes)?;
        // try to decode the threshold
        let (threshold, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        // try to decode the limit
        let (limit, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        // try to decode the key share data
        let (key_data, ptr) = Varbytes::try_decode_from(ptr)?;
        Ok((
            Self(
                id.to_inner(),
                NonZero::new(threshold.clone().to_inner())
                    .ok_or(Error::Threshold(ThresholdError::MustBeNonZero(*threshold)))?,
                NonZero::new(limit.clone().to_inner())
                    .ok_or(Error::Threshold(ThresholdError::MustBeNonZero(*limit)))?,
                key_data.to_inner(),
            ),
            ptr,
        ))
    }
}

#[derive(Clone, Default)]
pub(crate) struct ThresholdData(pub(crate) BTreeMap<u8, KeyShare>);

impl From<ThresholdData> for Vec<u8> {
    fn from(val: ThresholdData) -> Self {
        let mut v = Vec::default();
        // add in the number of key shares
        v.append(&mut Varuint(val.0.len()).into());
        // add in the key shares
        val.0.iter().for_each(|(_, share)| {
            v.append(&mut share.clone().into());
        });
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for ThresholdData {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (tdata, _) = Self::try_decode_from(bytes)?;
        Ok(tdata)
    }
}

impl<'a> TryDecodeFrom<'a> for ThresholdData {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // try to decode the number of shares
        let (num_shares, ptr) = Varuint::<usize>::try_decode_from(bytes)?;
        // decode the key-specific attributes
        let (shares, ptr) = match *num_shares {
            0 => (BTreeMap::default(), ptr),
            _ => {
                let mut shares = BTreeMap::new();
                let mut p = ptr;
                for _ in 0..*num_shares {
                    let (share, ptr) = KeyShare::try_decode_from(p)?;
                    shares.insert(share.0, share);
                    p = ptr;
                }
                (shares, p)
            }
        };

        Ok((Self(shares), ptr))
    }
}

pub(crate) struct View<'a> {
    mk: &'a Multikey,
}

impl<'a> TryFrom<&'a Multikey> for View<'a> {
    type Error = Error;

    fn try_from(mk: &'a Multikey) -> Result<Self, Self::Error> {
        Ok(Self { mk })
    }
}

impl AttrView for View<'_> {
    fn is_encrypted(&self) -> bool {
        if let Some(v) = self.mk.attributes.get(&AttrId::KeyIsEncrypted) {
            if let Ok(b) = Varuint::<bool>::try_from(v.as_slice()) {
                return b.to_inner();
            }
        }
        false
    }

    fn is_secret_key(&self) -> bool {
        matches!(
            self.mk.codec,
            Codec::Bls12381G1Priv
                | Codec::Bls12381G2Priv
                | Codec::Bls12381G1PrivShare
                | Codec::Bls12381G2PrivShare
        )
    }

    fn is_public_key(&self) -> bool {
        matches!(self.mk.codec, Codec::Bls12381G1Pub | Codec::Bls12381G2Pub)
    }

    fn is_secret_key_share(&self) -> bool {
        matches!(
            self.mk.codec,
            Codec::Bls12381G1PrivShare | Codec::Bls12381G2PrivShare
        )
    }
}

impl ThresholdAttrView for View<'_> {
    /// get the threshold value for the multikey
    fn threshold(&self) -> Result<NonZeroUsize, Error> {
        let v = self
            .mk
            .attributes
            .get(&AttrId::Threshold)
            .ok_or(AttributesError::MissingThreshold)?;
        Ok(NonZero::new(*Varuint::<usize>::try_from(v.as_slice())?).unwrap())
    }
    /// get the limit value for the multikey
    fn limit(&self) -> Result<NonZeroUsize, Error> {
        let v = self
            .mk
            .attributes
            .get(&AttrId::Limit)
            .ok_or(AttributesError::MissingLimit)?;
        // Ok(*Varuint::<usize>::try_from(v.as_slice())?)
        Ok(NonZero::new(*Varuint::<usize>::try_from(v.as_slice())?).unwrap())
    }
    /// get the share identifier for the multikey
    fn identifier(&self) -> Result<u8, Error> {
        let v = self
            .mk
            .attributes
            .get(&AttrId::ShareIdentifier)
            .ok_or(AttributesError::MissingShareIdentifier)?;
        Ok(*Varuint::<u8>::try_from(v.as_slice())?)
    }
    /// get the threshold data
    fn threshold_data(&self) -> Result<&[u8], Error> {
        let v = self
            .mk
            .attributes
            .get(&AttrId::ThresholdData)
            .ok_or(AttributesError::MissingThresholdData)?;
        Ok(v.as_slice())
    }
}

impl DataView for View<'_> {
    /// For Ed25519Pub and Ed25519Priv Multikey values, the key data is stored
    /// using the AttrId::Data attribute id.
    fn key_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let key = self
            .mk
            .attributes
            .get(&AttrId::KeyData)
            .ok_or(AttributesError::MissingKey)?;
        Ok(key.clone())
    }

    /// Check to see if this is a secret key before returning the key bytes
    fn secret_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        if !self.is_secret_key() {
            return Err(AttributesError::NotSecretKey(self.mk.codec).into());
        }
        if self.is_encrypted() {
            return Err(AttributesError::EncryptedKey.into());
        }
        self.key_bytes()
    }
}

impl CipherAttrView for View<'_> {
    fn cipher_codec(&self) -> Result<Codec, Error> {
        // try to look up the cipher codec in the multikey attributes
        let codec = self
            .mk
            .attributes
            .get(&AttrId::CipherCodec)
            .ok_or(CipherError::MissingCodec)?;
        Ok(Codec::try_from(codec.as_slice())?)
    }

    fn nonce_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        // try to look up the salt in the multikey attributes
        self.mk
            .attributes
            .get(&AttrId::CipherNonce)
            .ok_or(CipherError::MissingNonce.into())
            .cloned()
    }

    fn key_length(&self) -> Result<usize, Error> {
        // try to look up the cipher key length in the multikey attributes
        let key_length = self
            .mk
            .attributes
            .get(&AttrId::CipherKeyLen)
            .ok_or(CipherError::MissingKeyLen)?;
        Ok(Varuint::<usize>::try_from(key_length.as_slice())?.to_inner())
    }
}

impl KdfAttrView for View<'_> {
    fn kdf_codec(&self) -> Result<Codec, Error> {
        // try to look up the kdf codec in the multikey attributes
        let codec = self
            .mk
            .attributes
            .get(&AttrId::KdfCodec)
            .ok_or(KdfError::MissingCodec)?;
        Ok(Codec::try_from(codec.as_slice())?)
    }

    fn salt_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        // try to look up the salt in the multikey attributes
        self.mk
            .attributes
            .get(&AttrId::KdfSalt)
            .ok_or(KdfError::MissingSalt.into())
            .cloned()
    }

    fn rounds(&self) -> Result<usize, Error> {
        // try to look up the rounds in the multikey attributes
        let rounds = self
            .mk
            .attributes
            .get(&AttrId::KdfRounds)
            .ok_or(KdfError::MissingRounds)?;
        Ok(Varuint::<usize>::try_from(rounds.as_slice())?.to_inner())
    }
}

impl FingerprintView for View<'_> {
    fn fingerprint(&self, codec: Codec) -> Result<Multihash, Error> {
        let attr = self.mk.attr_view()?;
        if attr.is_secret_key() {
            // convert to a public key Multikey
            let pk = self.to_public_key()?;
            // get a conversions view on the public key
            let fp = pk.fingerprint_view()?;
            // get the fingerprint
            let f = fp.fingerprint(codec)?;
            Ok(f)
        } else {
            // get the key bytes
            let bytes = {
                let kd = self.mk.data_view()?;

                kd.key_bytes()?
            };
            // hash the key bytes using the given codec
            Ok(mh::Builder::new_from_bytes(codec, bytes)?.try_build()?)
        }
    }
}

impl ConvView for View<'_> {
    /// try to convert a secret key to a public key
    fn to_public_key(&self) -> Result<Multikey, Error> {
        // get the secret key bytes
        let secret_bytes = {
            let kd = self.mk.data_view()?;

            kd.secret_bytes()?
        };

        match self.mk.codec {
            Codec::Bls12381G1Priv => {
                let bytes: [u8; SECRET_KEY_BYTES] = secret_bytes.as_slice()[..SECRET_KEY_BYTES]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to get secret key bytes".to_string(),
                        )
                    })?;
                let secret_key: SecretKey<Bls12381G1Impl> = {
                    let sk = Option::from(SecretKey::from_be_bytes(&bytes));
                    sk.ok_or(ConversionsError::SecretKeyFailure(
                        "failed to create secret key".to_string(),
                    ))?
                };
                // get the public key and build a Multikey out of it
                let public_key = secret_key.public_key();
                let key_bytes = public_key.0.to_bytes();
                Builder::new(Codec::Bls12381G1Pub)
                    .with_comment(&self.mk.comment)
                    .with_key_bytes(&key_bytes)
                    .try_build()
            }
            Codec::Bls12381G1PrivShare => {
                let av = self.mk.threshold_attr_view()?;
                let threshold = av.threshold()?;
                let limit = av.limit()?;
                let identifier = av.identifier()?;

                let secret_key: SecretKeyShare<Bls12381G1Impl> = SecretKeyShare(
                    Share::with_identifier_and_value(identifier, secret_bytes.as_slice()),
                );

                // get the public key and build a Multikey out of it
                let public_key = secret_key
                    .public_key()
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
                let key_bytes = public_key.0 .0.value_vec();
                Builder::new(Codec::Bls12381G1PubShare)
                    .with_comment(&self.mk.comment)
                    .with_key_bytes(&key_bytes)
                    .with_threshold(threshold)
                    .with_limit(limit)
                    .with_identifier(identifier)
                    .try_build()
            }
            Codec::Bls12381G2Priv => {
                let bytes: [u8; SECRET_KEY_BYTES] = secret_bytes.as_slice()[..SECRET_KEY_BYTES]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to get secret key bytes".to_string(),
                        )
                    })?;
                let secret_key: SecretKey<Bls12381G2Impl> = {
                    let sk = Option::from(SecretKey::from_be_bytes(&bytes));
                    sk.ok_or(ConversionsError::SecretKeyFailure(
                        "failed to create secret key".to_string(),
                    ))?
                };
                // get the public key and build a Multikey out of it
                let public_key = secret_key.public_key();
                let key_bytes = public_key.0.to_bytes();
                Builder::new(Codec::Bls12381G2Pub)
                    .with_comment(&self.mk.comment)
                    .with_key_bytes(&key_bytes)
                    .try_build()
            }
            Codec::Bls12381G2PrivShare => {
                let av = self.mk.threshold_attr_view()?;
                let threshold = av.threshold()?;
                let limit = av.limit()?;
                let identifier = av.identifier()?;

                let secret_key: SecretKeyShare<Bls12381G2Impl> = SecretKeyShare(
                    Share::with_identifier_and_value(identifier, secret_bytes.as_slice()),
                );

                // get the public key and build a Multikey out of it
                let public_key = secret_key
                    .public_key()
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
                let key_bytes = public_key.0 .0.value_vec();
                Builder::new(Codec::Bls12381G1PubShare)
                    .with_comment(&self.mk.comment)
                    .with_key_bytes(&key_bytes)
                    .with_threshold(threshold)
                    .with_limit(limit)
                    .with_identifier(identifier)
                    .try_build()
            }
            _ => Err(ConversionsError::UnsupportedCodec(self.mk.codec).into()),
        }
    }

    /// try to convert a Multikey to an ssh_key::PublicKey
    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        let mut pk = self.mk.clone();
        if self.is_secret_key() {
            pk = self.to_public_key()?;
        }

        let key_bytes = {
            let kd = pk.data_view()?;

            kd.key_bytes()?
        };

        let mut buf: Vec<u8> = Vec::new();

        let name = match pk.codec {
            Codec::Bls12381G1Pub => {
                key_bytes
                    .encode(&mut buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                ALGORITHM_NAME_G1
            }
            Codec::Bls12381G1PubShare => {
                let tav = pk.threshold_attr_view()?;
                let key_share: Vec<u8> = KeyShare(
                    tav.identifier()?,
                    tav.threshold()?.into(),
                    tav.limit()?.into(),
                    key_bytes.to_vec(),
                )
                .into();
                key_share
                    .encode(&mut buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                ALGORITHM_NAME_G1_SHARE
            }
            Codec::Bls12381G2Pub => {
                key_bytes
                    .encode(&mut buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                ALGORITHM_NAME_G2
            }
            Codec::Bls12381G2PubShare => {
                let tav = pk.threshold_attr_view()?;
                let key_share: Vec<u8> = KeyShare(
                    tav.identifier()?,
                    tav.threshold()?.into(),
                    tav.limit()?,
                    key_bytes.to_vec(),
                )
                .into();
                key_share
                    .encode(&mut buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                ALGORITHM_NAME_G2_SHARE
            }
            _ => return Err(ConversionsError::UnsupportedCodec(self.mk.codec).into()),
        };

        let opaque_key_bytes = ssh_key::public::OpaquePublicKeyBytes::decode(&mut buf.as_slice())
            .map_err(|e| ConversionsError::Ssh(e.into()))?;

        Ok(ssh_key::PublicKey::new(
            ssh_key::public::KeyData::Other(ssh_key::public::OpaquePublicKey {
                algorithm: ssh_key::Algorithm::Other(
                    ssh_key::AlgorithmName::new(name)
                        .map_err(|e| ConversionsError::Ssh(e.into()))?,
                ),
                key: opaque_key_bytes,
            }),
            pk.comment,
        ))
    }

    /// try to convert a Multikey to an ssh_key::PrivateKey
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        let secret_bytes = {
            let kd = self.mk.data_view()?;

            kd.secret_bytes()?
        };

        let pk = self.to_public_key()?;
        let key_bytes = {
            let kd = pk.data_view()?;

            kd.key_bytes()?
        };

        let mut secret_buf: Vec<u8> = Vec::new();
        let mut public_buf: Vec<u8> = Vec::new();

        let name = match self.mk.codec {
            Codec::Bls12381G1Priv => {
                secret_bytes
                    .encode(&mut secret_buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                key_bytes
                    .encode(&mut public_buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                ALGORITHM_NAME_G1
            }
            Codec::Bls12381G1PrivShare => {
                let sav = self.mk.threshold_attr_view()?;
                let secret_key_share: Vec<u8> = KeyShare(
                    sav.identifier()?,
                    sav.threshold()?.into(),
                    sav.limit()?,
                    secret_bytes.to_vec(),
                )
                .into();
                let pav = pk.threshold_attr_view()?;
                let public_key_share: Vec<u8> = KeyShare(
                    pav.identifier()?,
                    pav.threshold()?.into(),
                    pav.limit()?,
                    key_bytes.to_vec(),
                )
                .into();
                secret_key_share
                    .encode(&mut secret_buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                public_key_share
                    .encode(&mut public_buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                ALGORITHM_NAME_G1_SHARE
            }
            Codec::Bls12381G2Priv => {
                secret_bytes
                    .encode(&mut secret_buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                key_bytes
                    .encode(&mut public_buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                ALGORITHM_NAME_G2
            }
            Codec::Bls12381G2PrivShare => {
                let sav = self.mk.threshold_attr_view()?;
                let secret_key_share: Vec<u8> = KeyShare(
                    sav.identifier()?,
                    sav.threshold()?.into(),
                    sav.limit()?,
                    secret_bytes.to_vec(),
                )
                .into();
                let pav = pk.threshold_attr_view()?;
                let public_key_share: Vec<u8> = KeyShare(
                    pav.identifier()?,
                    pav.threshold()?.into(),
                    pav.limit()?,
                    key_bytes.to_vec(),
                )
                .into();
                secret_key_share
                    .encode(&mut secret_buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                public_key_share
                    .encode(&mut public_buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                ALGORITHM_NAME_G2_SHARE
            }
            _ => return Err(ConversionsError::UnsupportedCodec(self.mk.codec).into()),
        };

        let opaque_private_key_bytes =
            ssh_key::private::OpaquePrivateKeyBytes::decode(&mut secret_buf.as_slice())
                .map_err(|e| ConversionsError::Ssh(e.into()))?;

        let opaque_public_key_bytes =
            ssh_key::public::OpaquePublicKeyBytes::decode(&mut public_buf.as_slice())
                .map_err(|e| ConversionsError::Ssh(e.into()))?;

        Ok(ssh_key::PrivateKey::new(
            ssh_key::private::KeypairData::Other(ssh_key::private::OpaqueKeypair {
                public: ssh_key::public::OpaquePublicKey {
                    algorithm: ssh_key::Algorithm::Other(
                        ssh_key::AlgorithmName::new(name)
                            .map_err(|e| ConversionsError::Ssh(e.into()))?,
                    ),
                    key: opaque_public_key_bytes,
                },
                private: opaque_private_key_bytes,
            }),
            self.mk.comment.clone(),
        )
        .map_err(|e| ConversionsError::Ssh(e.into()))?)
    }
}

impl SignView for View<'_> {
    /// try to create a Multisig by siging the passed-in data with the Multikey
    fn sign(&self, msg: &[u8], combined: bool, scheme: Option<u8>) -> Result<Multisig, Error> {
        let scheme = scheme.ok_or(SignError::MissingScheme)?;

        let attr = self.mk.attr_view()?;
        if !attr.is_secret_key() {
            return Err(SignError::NotSigningKey.into());
        }

        // get the secret key bytes
        let secret_bytes = {
            let kd = self.mk.data_view()?;

            kd.secret_bytes()?
        };

        // get the signature scheme
        let sig_scheme: SignatureSchemes = SchemeTypeId::try_from(scheme)?.into();

        match self.mk.codec {
            Codec::Bls12381G1Priv => {
                let bytes: [u8; SECRET_KEY_BYTES] = secret_bytes.as_slice()[..SECRET_KEY_BYTES]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to get secret key bytes".to_string(),
                        )
                    })?;
                let secret_key: SecretKey<Bls12381G1Impl> = {
                    let sk = Option::from(SecretKey::from_be_bytes(&bytes));
                    sk.ok_or(ConversionsError::SecretKeyFailure(
                        "failed to create secret key".to_string(),
                    ))?
                };
                // sign the data
                let signature = secret_key
                    .sign(sig_scheme, msg)
                    .map_err(|e| SignError::SigningFailed(e.to_string()))?;

                let mut ms = ms::Builder::new_from_bls_signature(&signature)?;
                if combined {
                    ms = ms.with_message_bytes(&msg);
                }
                Ok(ms.try_build()?)
            }
            Codec::Bls12381G1PrivShare => {
                let av = self.mk.threshold_attr_view()?;
                let threshold = av.threshold()?;
                let limit = av.limit()?;
                let identifier = av.identifier()?;

                let secret_key: SecretKeyShare<Bls12381G1Impl> = SecretKeyShare(
                    Share::with_identifier_and_value(identifier, secret_bytes.as_slice()),
                );

                // sign the data
                let signature = secret_key
                    .sign(sig_scheme, msg)
                    .map_err(|e| SignError::SigningFailed(e.to_string()))?;

                let mut ms =
                    ms::Builder::new_from_bls_signature_share(threshold, limit, &signature)?;
                if combined {
                    ms = ms.with_message_bytes(&msg);
                }
                Ok(ms.try_build()?)
            }
            Codec::Bls12381G2Priv => {
                let bytes: [u8; SECRET_KEY_BYTES] = secret_bytes.as_slice()[..SECRET_KEY_BYTES]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to get secret key bytes".to_string(),
                        )
                    })?;
                let secret_key: SecretKey<Bls12381G2Impl> = {
                    let sk = Option::from(SecretKey::from_be_bytes(&bytes));
                    sk.ok_or(ConversionsError::SecretKeyFailure(
                        "failed to create secret key".to_string(),
                    ))?
                };
                // sign the data
                let signature = secret_key
                    .sign(sig_scheme, msg)
                    .map_err(|e| SignError::SigningFailed(e.to_string()))?;

                let mut ms = ms::Builder::new_from_bls_signature(&signature)?;
                if combined {
                    ms = ms.with_message_bytes(&msg);
                }
                Ok(ms.try_build()?)
            }
            Codec::Bls12381G2PrivShare => {
                let av = self.mk.threshold_attr_view()?;
                let threshold = av.threshold()?;
                let limit = av.limit()?;
                let identifier = av.identifier()?;

                let secret_key: SecretKeyShare<Bls12381G2Impl> = SecretKeyShare(
                    Share::with_identifier_and_value(identifier, secret_bytes.as_slice()),
                );

                // sign the data
                let signature = secret_key
                    .sign(sig_scheme, msg)
                    .map_err(|e| SignError::SigningFailed(e.to_string()))?;
                let mut ms =
                    ms::Builder::new_from_bls_signature_share(threshold, limit, &signature)?;
                if combined {
                    ms = ms.with_message_bytes(&msg);
                }
                Ok(ms.try_build()?)
            }
            _ => Err(ConversionsError::UnsupportedCodec(self.mk.codec).into()),
        }
    }
}

impl ThresholdView for View<'_> {
    /// try to split a Multikey into shares
    fn split(&self, threshold: NonZeroUsize, limit: NonZeroUsize) -> Result<Vec<Multikey>, Error> {
        if threshold > limit {
            return Err(ThresholdError::InvalidThresholdLimit(threshold, limit).into());
        }

        let attr = self.mk.attr_view()?;
        if !attr.is_secret_key() {
            return Err(ThresholdError::NotASecretKey.into());
        }

        // get the secret key bytes
        let secret_bytes = {
            let kd = self.mk.data_view()?;

            kd.secret_bytes()?
        };

        match self.mk.codec {
            Codec::Bls12381G1Priv => {
                let bytes: [u8; SECRET_KEY_BYTES] = secret_bytes.as_slice()[..SECRET_KEY_BYTES]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to get secret key bytes".to_string(),
                        )
                    })?;
                let secret_key: SecretKey<Bls12381G1Impl> = {
                    let sk = Option::from(SecretKey::from_be_bytes(&bytes));
                    sk.ok_or(ConversionsError::SecretKeyFailure(
                        "failed to create secret key".to_string(),
                    ))?
                };
                let key_shares = secret_key
                    .split(threshold.into(), limit.into())
                    .map_err(ThresholdError::Bls)?;

                let mut shares = Vec::with_capacity(key_shares.len());

                key_shares
                    .iter()
                    .try_for_each(|share| -> Result<(), Error> {
                        let key_bytes = share.as_raw_value().value_vec();
                        let identifier = share.as_raw_value().identifier();

                        let mk = Builder::new(Codec::Bls12381G1PrivShare)
                            .with_comment(&self.mk.comment)
                            .with_key_bytes(&key_bytes)
                            .with_threshold(threshold)
                            .with_limit(limit)
                            .with_identifier(identifier)
                            .try_build()?;
                        shares.push(mk);
                        Ok(())
                    })?;

                Ok(shares)
            }
            Codec::Bls12381G2Priv => {
                let bytes: [u8; SECRET_KEY_BYTES] = secret_bytes.as_slice()[..SECRET_KEY_BYTES]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to get secret key bytes".to_string(),
                        )
                    })?;
                let secret_key: SecretKey<Bls12381G2Impl> = {
                    let sk = Option::from(SecretKey::from_be_bytes(&bytes));
                    sk.ok_or(ConversionsError::SecretKeyFailure(
                        "failed to create secret key".to_string(),
                    ))?
                };

                let key_shares = secret_key
                    .split(threshold.into(), limit.into())
                    .map_err(ThresholdError::Bls)?;

                let mut shares = Vec::with_capacity(key_shares.len());

                key_shares
                    .iter()
                    .try_for_each(|share| -> Result<(), Error> {
                        let key_bytes = share.as_raw_value().value_vec();
                        let identifier = share.as_raw_value().identifier();

                        let mk = Builder::new(Codec::Bls12381G2PrivShare)
                            .with_comment(&self.mk.comment)
                            .with_key_bytes(&key_bytes)
                            .with_threshold(threshold)
                            .with_limit(limit)
                            .with_identifier(identifier)
                            .try_build()?;
                        shares.push(mk);
                        Ok(())
                    })?;

                Ok(shares)
            }
            _ => Err(ConversionsError::UnsupportedCodec(self.mk.codec).into()),
        }
    }

    /// add a new share and return the Multikey with the share added
    fn add_share(&self, share: &Multikey) -> Result<Multikey, Error> {
        // this only makes sense for secret keys
        match self.mk.codec {
            Codec::Bls12381G1Priv | Codec::Bls12381G2Priv => {}
            Codec::Bls12381G1Pub | Codec::Bls12381G2Pub => {
                return Err(ThresholdError::NotASecretKey.into())
            }
            Codec::Bls12381G1PubShare
            | Codec::Bls12381G1PrivShare
            | Codec::Bls12381G2PubShare
            | Codec::Bls12381G2PrivShare => return Err(ThresholdError::IsAKeyShare.into()),
            _ => return Err(Error::UnsupportedAlgorithm(self.mk.codec.to_string())),
        }

        let (key_share, identifier, threshold, limit) = {
            // get the share attributes
            let av = share.threshold_attr_view()?;
            let identifier = av.identifier()?;
            let threshold = av.threshold()?;
            let limit = av.limit()?;
            // get the key data
            let dv = share.data_view()?;
            let key_bytes = dv.key_bytes()?;
            // return the data
            (
                KeyShare(identifier, threshold, limit, key_bytes.to_vec()),
                identifier,
                threshold,
                limit,
            )
        };

        let threshold_data: Vec<u8> = {
            let av = self.mk.threshold_attr_view()?;
            let mut tdata = match av.threshold_data() {
                Ok(b) => ThresholdData::try_from(b).unwrap_or_default(),
                Err(_) => ThresholdData::default(),
            };
            // insert the share data
            tdata.0.insert(identifier, key_share);
            tdata.into()
        };

        // if this multikey doesn't already have the threshold/limi set, then
        // set it to match the values from the first share
        let av = share.threshold_attr_view()?;
        let threshold = av.threshold().unwrap_or(threshold);
        let limit = av.limit().unwrap_or(limit);
        let comment = if self.mk.comment.is_empty() {
            share.comment.clone()
        } else {
            String::default()
        };

        Builder::new(self.mk.codec)
            .with_comment(&comment)
            .with_threshold(threshold)
            .with_limit(limit)
            .with_threshold_data(&threshold_data)
            .try_build()
    }

    /// reconstruct the key from teh shares
    fn combine(&self) -> Result<Multikey, Error> {
        // get the current threshold data
        let (threshold_data, threshold) = {
            let av = self.mk.threshold_attr_view()?;
            (
                match av.threshold_data() {
                    Ok(b) => ThresholdData::try_from(b).unwrap_or_default(),
                    Err(_) => ThresholdData::default(),
                },
                av.threshold()?,
            )
        };

        // check that we have enough shares to combine
        let num_shares = threshold_data.0.len();
        if num_shares < threshold.into() {
            return Err(ThresholdError::NotEnoughShares.into());
        }

        match self.mk.codec {
            Codec::Bls12381G1Priv => {
                let mut shares = Vec::with_capacity(threshold_data.0.len());
                threshold_data
                    .0
                    .iter()
                    .try_for_each(|(id, share)| -> Result<(), Error> {
                        let vsss = Share::with_identifier_and_value(*id, share.3.as_slice());
                        shares.push(SecretKeyShare::<Bls12381G1Impl>(vsss));
                        Ok(())
                    })?;
                let key = SecretKey::combine(shares.as_slice())
                    .map_err(|e| ThresholdError::ShareCombineFailed(e.to_string()))?;
                let key_bytes = key.to_be_bytes().to_vec();
                Builder::new(Codec::Bls12381G1Priv)
                    .with_comment(&self.mk.comment)
                    .with_key_bytes(&key_bytes)
                    .try_build()
            }
            Codec::Bls12381G2Priv => {
                let mut shares = Vec::with_capacity(threshold_data.0.len());
                threshold_data
                    .0
                    .iter()
                    .try_for_each(|(id, share)| -> Result<(), Error> {
                        let vsss = Share::with_identifier_and_value(*id, share.3.as_slice());
                        shares.push(SecretKeyShare::<Bls12381G2Impl>(vsss));
                        Ok(())
                    })?;
                let key = SecretKey::combine(shares.as_slice())
                    .map_err(|e| ThresholdError::ShareCombineFailed(e.to_string()))?;
                let key_bytes = key.to_be_bytes().to_vec();
                Builder::new(Codec::Bls12381G2Priv)
                    .with_comment(&self.mk.comment)
                    .with_key_bytes(&key_bytes)
                    .try_build()
            }
            _ => Err(Error::UnsupportedAlgorithm(self.mk.codec.to_string())),
        }
    }
}

impl VerifyView for View<'_> {
    /// try to verify a Multisig using the Multikey
    fn verify(&self, multisig: &Multisig, msg: Option<&[u8]>) -> Result<(), Error> {
        let attr = self.mk.attr_view()?;
        let pubmk = if attr.is_secret_key() {
            let kc = self.mk.conv_view()?;

            kc.to_public_key()?
        } else {
            self.mk.clone()
        };

        // get the secret key bytes
        let key_bytes = {
            let kd = pubmk.data_view()?;
            let key_bytes = kd.key_bytes()?;
            key_bytes.to_vec()
        };

        // get the signature scheme
        let av = multisig.attr_view()?;
        let sig_scheme = SchemeTypeId::try_from(av.scheme()?)?;

        match pubmk.codec {
            Codec::Bls12381G1Pub => {
                // build a blsful::PublicKey from the bytes
                let public_key = PublicKey::try_from(&key_bytes)
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;

                // get the signature data
                let sv = multisig.data_view()?;
                let sig = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;

                let group_encoding: G1Projective = {
                    let bytes: [u8; G1_PUBLIC_KEY_BYTES] = sig.as_slice()[..G1_PUBLIC_KEY_BYTES]
                        .try_into()
                        .map_err(|e: TryFromSliceError| VerifyError::BadSignature(e.to_string()))?;
                    let res = Option::from(G1Projective::from_compressed(&bytes));
                    res.ok_or(VerifyError::BadSignature(
                        "failed to deserialize group encoding".to_string(),
                    ))?
                };

                let sig = match sig_scheme {
                    SchemeTypeId::Basic => Signature::<Bls12381G1Impl>::Basic(group_encoding),
                    SchemeTypeId::MessageAugmentation => {
                        Signature::<Bls12381G1Impl>::MessageAugmentation(group_encoding)
                    }
                    SchemeTypeId::ProofOfPossession => {
                        Signature::<Bls12381G1Impl>::ProofOfPossession(group_encoding)
                    }
                };

                // get the message
                let msg = if let Some(msg) = msg {
                    msg
                } else if !multisig.message.is_empty() {
                    multisig.message.as_slice()
                } else {
                    return Err(VerifyError::MissingMessage.into());
                };

                Ok(sig
                    .verify(&public_key, msg)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?)
            }
            Codec::Bls12381G1PubShare => {
                // build a blsful::PublicKeyShare from the bytes
                let public_key = PublicKeyShare::try_from(&key_bytes)
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;

                // get the share identifier
                let av = multisig.threshold_attr_view()?;
                let identifier = av.identifier()?;

                // get the signature data
                let sv = multisig.data_view()?;
                let value = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;

                let share = Share::with_identifier_and_value(identifier, &value);

                let sig = match sig_scheme {
                    SchemeTypeId::Basic => SignatureShare::<Bls12381G1Impl>::Basic(share),
                    SchemeTypeId::MessageAugmentation => {
                        SignatureShare::<Bls12381G1Impl>::MessageAugmentation(share)
                    }
                    SchemeTypeId::ProofOfPossession => {
                        SignatureShare::<Bls12381G1Impl>::ProofOfPossession(share)
                    }
                };

                // get the message
                let msg = if let Some(msg) = msg {
                    msg
                } else if !multisig.message.is_empty() {
                    multisig.message.as_slice()
                } else {
                    return Err(VerifyError::MissingMessage.into());
                };

                Ok(sig
                    .verify(&public_key, msg)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?)
            }
            Codec::Bls12381G2Pub => {
                // build a blsful::PublicKey from the bytes
                let public_key = PublicKey::try_from(&key_bytes)
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;

                // get the signature data
                let sv = multisig.data_view()?;
                let sig = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;

                let group_encoding: G2Projective = {
                    let bytes: [u8; G2_PUBLIC_KEY_BYTES] = sig.as_slice()[..G2_PUBLIC_KEY_BYTES]
                        .try_into()
                        .map_err(|e: TryFromSliceError| VerifyError::BadSignature(e.to_string()))?;
                    let res = Option::from(G2Projective::from_compressed(&bytes));
                    res.ok_or(VerifyError::BadSignature(
                        "failed to deserialize group encoding".to_string(),
                    ))?
                };

                let sig = match sig_scheme {
                    SchemeTypeId::Basic => Signature::<Bls12381G2Impl>::Basic(group_encoding),
                    SchemeTypeId::MessageAugmentation => {
                        Signature::<Bls12381G2Impl>::MessageAugmentation(group_encoding)
                    }
                    SchemeTypeId::ProofOfPossession => {
                        Signature::<Bls12381G2Impl>::ProofOfPossession(group_encoding)
                    }
                };

                // get the message
                let msg = if let Some(msg) = msg {
                    msg
                } else if !multisig.message.is_empty() {
                    multisig.message.as_slice()
                } else {
                    return Err(VerifyError::MissingMessage.into());
                };

                Ok(sig
                    .verify(&public_key, msg)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?)
            }
            Codec::Bls12381G2PubShare => {
                // build a blsful::PublicKeyShare from the bytes
                let public_key = PublicKeyShare::try_from(&key_bytes)
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;

                // get the share identifier
                let av = multisig.threshold_attr_view()?;
                let identifier = av.identifier()?;

                // get the signature data
                let sv = multisig.data_view()?;
                let value = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;

                let share = Share::with_identifier_and_value(identifier, &value);

                let sig = match sig_scheme {
                    SchemeTypeId::Basic => SignatureShare::<Bls12381G1Impl>::Basic(share),
                    SchemeTypeId::MessageAugmentation => {
                        SignatureShare::<Bls12381G1Impl>::MessageAugmentation(share)
                    }
                    SchemeTypeId::ProofOfPossession => {
                        SignatureShare::<Bls12381G1Impl>::ProofOfPossession(share)
                    }
                };

                // get the message
                let msg = if let Some(msg) = msg {
                    msg
                } else if !multisig.message.is_empty() {
                    multisig.message.as_slice()
                } else {
                    return Err(VerifyError::MissingMessage.into());
                };

                Ok(sig
                    .verify(&public_key, msg)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?)
            }
            _ => Err(ConversionsError::UnsupportedCodec(self.mk.codec).into()),
        }
    }
}
