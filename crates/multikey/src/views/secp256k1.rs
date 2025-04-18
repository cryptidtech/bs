// SPDX-License-Idnetifier: Apache-2.0
use crate::{
    error::{AttributesError, CipherError, ConversionsError, KdfError, SignError, VerifyError},
    AttrId, AttrView, Builder, CipherAttrView, ConvView, DataView, Error, FingerprintView,
    KdfAttrView, Multikey, SignView, VerifyView, Views,
};

use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use multicodec::Codec;
use multihash::{mh, Multihash};
use multisig::{ms, Multisig, Views as SigViews};
use multitrait::TryDecodeFrom;
use multiutil::Varuint;
use ssh_encoding::{Decode, Encode};
use zeroize::Zeroizing;

/// the number of bytes in an secp256k1 secret key
pub const SECRET_KEY_LENGTH: usize = 32;
/// the number of bytes in an secp256k1 public key
pub const PUBLIC_KEY_LENGTH: usize = 33;
/// the RFC 4251 algorithm name for SSH compatibility
pub const ALGORITHM_NAME: &str = "secp256k1@multikey";

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
            if let Ok((b, _)) = Varuint::<bool>::try_decode_from(v.as_slice()) {
                return b.to_inner();
            }
        }
        false
    }

    fn is_secret_key(&self) -> bool {
        self.mk.codec == Codec::Secp256K1Priv
    }

    fn is_public_key(&self) -> bool {
        self.mk.codec == Codec::Secp256K1Pub
    }

    fn is_secret_key_share(&self) -> bool {
        false
    }
}

impl DataView for View<'_> {
    /// For Secp256K1Pub and Secp256K1Priv Multikey values, the key data is stored
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

        // build an secp256k1 signing key so that we can derive the verifying key
        let bytes: [u8; SECRET_KEY_LENGTH] = secret_bytes.as_slice()[..SECRET_KEY_LENGTH]
            .try_into()
            .map_err(|_| {
                ConversionsError::SecretKeyFailure("failed to get secret key bytes".to_string())
            })?;
        let secret_key = SigningKey::from_bytes(&bytes.into())
            .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;
        // get the public key and build a Multikey out of it
        let public_key = secret_key.verifying_key();
        Builder::new(Codec::Secp256K1Pub)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&public_key.to_sec1_bytes())
            .try_build()
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

        let mut buff: Vec<u8> = Vec::new();
        key_bytes
            .encode(&mut buff)
            .map_err(|e| ConversionsError::Ssh(e.into()))?;
        let opaque_key_bytes = ssh_key::public::OpaquePublicKeyBytes::decode(&mut buff.as_slice())
            .map_err(|e| ConversionsError::Ssh(e.into()))?;

        Ok(ssh_key::PublicKey::new(
            ssh_key::public::KeyData::Other(ssh_key::public::OpaquePublicKey {
                algorithm: ssh_key::Algorithm::Other(
                    ssh_key::AlgorithmName::new(ALGORITHM_NAME)
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

        let mut buf: Vec<u8> = Vec::new();
        secret_bytes
            .encode(&mut buf)
            .map_err(|e| ConversionsError::Ssh(e.into()))?;
        let opaque_private_key_bytes =
            ssh_key::private::OpaquePrivateKeyBytes::decode(&mut buf.as_slice())
                .map_err(|e| ConversionsError::Ssh(e.into()))?;

        let pk = self.to_public_key()?;
        let key_bytes = {
            let kd = pk.data_view()?;

            kd.key_bytes()?
        };

        buf.clear();
        key_bytes
            .encode(&mut buf)
            .map_err(|e| ConversionsError::Ssh(e.into()))?;
        let opaque_public_key_bytes =
            ssh_key::public::OpaquePublicKeyBytes::decode(&mut buf.as_slice())
                .map_err(|e| ConversionsError::Ssh(e.into()))?;

        Ok(ssh_key::PrivateKey::new(
            ssh_key::private::KeypairData::Other(ssh_key::private::OpaqueKeypair {
                public: ssh_key::public::OpaquePublicKey {
                    algorithm: ssh_key::Algorithm::Other(
                        ssh_key::AlgorithmName::new(ALGORITHM_NAME)
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
    fn sign(&self, msg: &[u8], combined: bool, _scheme: Option<u8>) -> Result<Multisig, Error> {
        let attr = self.mk.attr_view()?;
        if !attr.is_secret_key() {
            return Err(SignError::NotSigningKey.into());
        }

        // get the secret key bytes
        let secret_bytes = {
            let kd = self.mk.data_view()?;

            kd.secret_bytes()?
        };

        let secret_key = {
            // build an secp256k1 signing key so that we can derive the verifying key
            let bytes: [u8; SECRET_KEY_LENGTH] = secret_bytes.as_slice()[..SECRET_KEY_LENGTH]
                .try_into()
                .map_err(|_| {
                    ConversionsError::SecretKeyFailure("failed to get secret key bytes".to_string())
                })?;

            SigningKey::from_bytes(&bytes.into())
                .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?
        };

        // sign the data
        let signature: Signature = secret_key
            .try_sign(msg)
            .map_err(|e| SignError::SigningFailed(e.to_string()))?;

        let mut ms =
            ms::Builder::new(Codec::Es256KMsig).with_signature_bytes(&signature.to_bytes());
        if combined {
            ms = ms.with_message_bytes(&msg);
        }
        Ok(ms.try_build()?)
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

            kd.key_bytes()?
        };

        // build an secp256k1 verifying key so that we can derive the verifying key
        let bytes: [u8; PUBLIC_KEY_LENGTH] = key_bytes.as_slice()[..PUBLIC_KEY_LENGTH]
            .try_into()
            .map_err(|_| {
            ConversionsError::PublicKeyFailure("failed to get public key bytes".to_string())
        })?;

        // create the verifying key
        let verifying_key = VerifyingKey::from_sec1_bytes(&bytes)
            .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;

        // get the signature data
        let sv = multisig.data_view()?;
        let sig = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;

        // create the signature
        let sig = Signature::from_slice(sig.as_slice())
            .map_err(|e| VerifyError::BadSignature(e.to_string()))?;

        // get the message
        let msg = if let Some(msg) = msg {
            msg
        } else if !multisig.message.is_empty() {
            multisig.message.as_slice()
        } else {
            return Err(VerifyError::MissingMessage.into());
        };

        verifying_key.verify(msg, &sig).map_err(|e| {
            println!("{}", e);
            VerifyError::BadSignature(e.to_string())
        })?;

        Ok(())
    }
}
