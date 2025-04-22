use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
// SPDX-License-Identifier: Apache-2.0
use crate::error::{AttributesError, CipherError, ConversionsError, KdfError};
use crate::{
    AttrId, AttrView, Builder, CipherAttrView, CipherView, ConvView, DataView, Error,
    FingerprintView, KdfAttrView, Multikey, Views,
};
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    Ciphertext, EncodedSizeUser, MlKem1024, MlKem1024Params, MlKem512, MlKem512Params, MlKem768,
    MlKem768Params,
};
use multicodec::Codec;
use multihash::{mh, Multihash};
use multiutil::Varuint;
use sha3::{
    digest::{ExtendableOutput, Update},
    Shake256,
};
use ssh_encoding::{Decode, Encode};
use zeroize::{Zeroize, Zeroizing};

pub const ALGORITHM_NAME_512: &str = "mlkem512@multikey";
pub const ALGORITHM_NAME_768: &str = "mlkem768@multikey";
pub const ALGORITHM_NAME_1024: &str = "mlkem1024@multikey";

pub const ML512_PUBLIC_KEY_SIZE: usize = 800;
pub const ML512_SECRET_KEY_SIZE: usize = 1632;
pub const ML512_CIPHERTEXT_SIZE: usize = 768;

pub const ML768_PUBLIC_KEY_SIZE: usize = 1184;
pub const ML768_SECRET_KEY_SIZE: usize = 2400;
pub const ML768_CIPHERTEXT_SIZE: usize = 1088;

pub const ML1024_PUBLIC_KEY_SIZE: usize = 1568;
pub const ML1024_SECRET_KEY_SIZE: usize = 3168;
pub const ML1024_CIPHERTEXT_SIZE: usize = 1568;

/// Return the length of the [Nonce]
#[allow(dead_code)]
pub(crate) fn nonce_length(_codec: Codec) -> Result<usize, Error> {
    Ok(32)
}

/// Return the length of the keys
#[allow(dead_code)]
pub(crate) fn key_length(codec: Codec) -> Result<usize, Error> {
    match codec {
        Codec::Mlkem512Priv => Ok(1632),
        Codec::Mlkem768Priv => Ok(2400),
        Codec::Mlkem1024Priv => Ok(3168),
        _ => Err(CipherError::UnsupportedCodec(codec).into()),
    }
}

pub(crate) struct View<'a> {
    mk: &'a Multikey,
    cipher: Option<&'a Multikey>,
}

impl<'a> View<'a> {
    pub fn new(mk: &'a Multikey, cipher: &'a Multikey) -> Self {
        Self {
            mk,
            cipher: Some(cipher),
        }
    }
}

impl<'a> TryFrom<&'a Multikey> for View<'a> {
    type Error = Error;

    fn try_from(mk: &'a Multikey) -> Result<Self, Self::Error> {
        Ok(Self { mk, cipher: None })
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
            Codec::Mlkem512Priv | Codec::Mlkem768Priv | Codec::Mlkem1024Priv
        )
    }

    fn is_public_key(&self) -> bool {
        matches!(
            self.mk.codec,
            Codec::Mlkem512Pub | Codec::Mlkem768Pub | Codec::Mlkem1024Pub
        )
    }

    fn is_secret_key_share(&self) -> bool {
        false
    }
}

impl DataView for View<'_> {
    fn key_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let key = self
            .mk
            .attributes
            .get(&AttrId::KeyData)
            .ok_or(AttributesError::MissingKey)?;
        Ok(key.clone())
    }

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
        let codec = self
            .mk
            .attributes
            .get(&AttrId::CipherCodec)
            .ok_or(CipherError::MissingCodec)?;
        Ok(Codec::try_from(codec.as_slice())?)
    }

    fn nonce_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.mk
            .attributes
            .get(&AttrId::CipherNonce)
            .ok_or(CipherError::MissingNonce.into())
            .cloned()
    }

    fn key_length(&self) -> Result<usize, Error> {
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
        let codec = self
            .mk
            .attributes
            .get(&AttrId::KdfCodec)
            .ok_or(KdfError::MissingCodec)?;
        Ok(Codec::try_from(codec.as_slice())?)
    }

    fn salt_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.mk
            .attributes
            .get(&AttrId::KdfSalt)
            .ok_or(KdfError::MissingSalt.into())
            .cloned()
    }

    fn rounds(&self) -> Result<usize, Error> {
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
            let pk = self.to_public_key()?;
            let fp = pk.fingerprint_view()?;
            let f = fp.fingerprint(codec)?;
            Ok(f)
        } else {
            let bytes = {
                let kd = self.mk.data_view()?;
                kd.key_bytes()?
            };
            Ok(mh::Builder::new_from_bytes(codec, bytes)?.try_build()?)
        }
    }
}

impl ConvView for View<'_> {
    fn to_public_key(&self) -> Result<Multikey, Error> {
        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };

        match self.mk.codec {
            Codec::Mlkem512Priv => {
                let bytes = secret_bytes.as_slice()[..ML512_SECRET_KEY_SIZE]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to convert secret key to public key".to_string(),
                        )
                    })?;
                let dk = DecapsulationKey::<MlKem512Params>::from_bytes(&bytes);
                let ek = dk.encapsulation_key();
                let key_bytes = ek.as_bytes();
                Builder::new(Codec::Mlkem512Pub)
                    .with_comment(&self.mk.comment)
                    .with_key_bytes(&key_bytes)
                    .try_build()
            }
            Codec::Mlkem768Priv => {
                let bytes = secret_bytes.as_slice()[..ML768_SECRET_KEY_SIZE]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to convert secret key to public key".to_string(),
                        )
                    })?;
                let dk = DecapsulationKey::<MlKem768Params>::from_bytes(&bytes);
                let ek = dk.encapsulation_key();
                let key_bytes = ek.as_bytes();
                Builder::new(Codec::Mlkem768Pub)
                    .with_comment(&self.mk.comment)
                    .with_key_bytes(&key_bytes)
                    .try_build()
            }
            Codec::Mlkem1024Priv => {
                let bytes = secret_bytes.as_slice()[..ML1024_SECRET_KEY_SIZE]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to convert secret key to public key".to_string(),
                        )
                    })?;
                let dk = DecapsulationKey::<MlKem1024Params>::from_bytes(&bytes);
                let ek = dk.encapsulation_key();
                let key_bytes = ek.as_bytes();
                Builder::new(Codec::Mlkem768Pub)
                    .with_comment(&self.mk.comment)
                    .with_key_bytes(&key_bytes)
                    .try_build()
            }
            _ => Err(ConversionsError::UnsupportedCodec(self.mk.codec).into()),
        }
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        let mut pk = self.mk.clone();
        if self.is_secret_key() {
            pk = self.to_public_key()?;
        }

        let key_bytes = pk.data_view()?.key_bytes()?;

        let mut buf: Vec<u8> = Vec::new();

        let name = match pk.codec {
            Codec::Mlkem512Pub => {
                buf.reserve_exact(ML512_PUBLIC_KEY_SIZE);
                key_bytes
                    .encode(&mut buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                ALGORITHM_NAME_512
            }
            Codec::Mlkem768Pub => {
                buf.reserve_exact(ML768_PUBLIC_KEY_SIZE);
                key_bytes
                    .encode(&mut buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                ALGORITHM_NAME_768
            }
            Codec::Mlkem1024Pub => {
                buf.reserve_exact(ML1024_PUBLIC_KEY_SIZE);
                key_bytes
                    .encode(&mut buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                ALGORITHM_NAME_1024
            }
            _ => return Err(ConversionsError::UnsupportedCodec(pk.codec).into()),
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

    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        let secret_bytes = self.mk.data_view()?.secret_bytes()?;

        let pk = self.to_public_key()?;
        let key_bytes = pk.data_view()?.key_bytes()?;

        let mut secret_buf = Vec::<u8>::new();
        let mut public_buf = Vec::<u8>::new();

        let name = match self.mk.codec {
            Codec::Mlkem512Priv => {
                secret_buf.reserve_exact(ML512_SECRET_KEY_SIZE);
                secret_bytes
                    .encode(&mut secret_buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                key_bytes
                    .encode(&mut public_buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                ALGORITHM_NAME_512
            }
            Codec::Mlkem768Priv => {
                secret_buf.reserve_exact(ML768_SECRET_KEY_SIZE);
                secret_bytes
                    .encode(&mut secret_buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                key_bytes
                    .encode(&mut public_buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                ALGORITHM_NAME_768
            }
            Codec::Mlkem1024Priv => {
                secret_buf.reserve_exact(ML1024_SECRET_KEY_SIZE);
                secret_bytes
                    .encode(&mut secret_buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                key_bytes
                    .encode(&mut public_buf)
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                ALGORITHM_NAME_1024
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

impl CipherView for View<'_> {
    fn decrypt(&self) -> Result<Multikey, Error> {
        let cipher = self.cipher.ok_or(CipherError::MissingCodec)?;

        let attr = self.mk.attr_view()?;
        if !attr.is_encrypted() || !attr.is_secret_key() {
            return Err(CipherError::DecryptionFailed.into());
        }

        let key = {
            let key = cipher.data_view()?.secret_bytes()?;
            if key.len() != self.key_length()? {
                return Err(CipherError::InvalidKey.into());
            }
            key
        };

        let ct = {
            let attr = self.mk.data_view()?;
            attr.key_bytes()?
        };

        let (mut sh, payload) = match cipher.codec {
            Codec::Mlkem512Priv => {
                let bytes = key.as_slice()[..ML512_SECRET_KEY_SIZE]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to convert secret key to public key".to_string(),
                        )
                    })?;
                let capsule = Ciphertext::<MlKem512>::try_from(&ct[..ML512_CIPHERTEXT_SIZE])
                    .map_err(|_| CipherError::DecryptionFailed)?;
                let dk = DecapsulationKey::<MlKem512Params>::from_bytes(&bytes);
                let sh = dk
                    .decapsulate(&capsule)
                    .map_err(|_| CipherError::DecryptionFailed)?;
                (sh, ct[ML512_CIPHERTEXT_SIZE..].to_vec())
            }
            Codec::Mlkem768Priv => {
                let bytes = key.as_slice()[..ML768_SECRET_KEY_SIZE]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to convert secret key to public key".to_string(),
                        )
                    })?;
                let capsule = Ciphertext::<MlKem768>::try_from(&ct[..ML768_CIPHERTEXT_SIZE])
                    .map_err(|_| CipherError::DecryptionFailed)?;
                let dk = DecapsulationKey::<MlKem768Params>::from_bytes(&bytes);
                let sh = dk
                    .decapsulate(&capsule)
                    .map_err(|_| CipherError::DecryptionFailed)?;
                (sh, ct[ML768_CIPHERTEXT_SIZE..].to_vec())
            }
            Codec::Mlkem1024Priv => {
                let bytes = key.as_slice()[..ML1024_SECRET_KEY_SIZE]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to convert secret key to public key".to_string(),
                        )
                    })?;
                let capsule = Ciphertext::<MlKem1024>::try_from(&ct[..ML1024_CIPHERTEXT_SIZE])
                    .map_err(|_| CipherError::DecryptionFailed)?;
                let dk = DecapsulationKey::<MlKem1024Params>::from_bytes(&bytes);
                let sh = dk
                    .decapsulate(&capsule)
                    .map_err(|_| CipherError::DecryptionFailed)?;
                (sh, ct[ML512_CIPHERTEXT_SIZE..].to_vec())
            }
            _ => return Err(CipherError::UnsupportedCodec(cipher.codec).into()),
        };

        let mut shake = Shake256::default();
        shake.update(&ct[..ct.len() - payload.len()]);
        shake.update(&sh);
        sh.zeroize();
        let mut kdf = shake.finalize_boxed(56);

        let mut nonce = XNonce::from_exact_iter(kdf[..24].iter().copied()).ok_or(
            CipherError::EncryptionFailed("invalid nonce bytes".to_string()),
        )?;
        let mut key = Key::from_exact_iter(kdf[24..].iter().copied()).ok_or(
            CipherError::EncryptionFailed("invalid key bytes".to_string()),
        )?;
        let chacha = XChaCha20Poly1305::new(&key);
        let plaintext = Zeroizing::new(
            chacha
                .decrypt(&nonce, &*payload)
                .map_err(|e| CipherError::EncryptionFailed(e.to_string()))?,
        );

        kdf.zeroize();
        nonce.zeroize();
        key.zeroize();

        let mut res = self.mk.clone();
        let _ = res.attributes.remove(&AttrId::KeyIsEncrypted);
        res.attributes.insert(AttrId::KeyData, plaintext);
        let _ = res.attributes.remove(&AttrId::CipherCodec);
        let _ = res.attributes.remove(&AttrId::CipherKeyLen);
        let _ = res.attributes.remove(&AttrId::KdfCodec);
        let _ = res.attributes.remove(&AttrId::KdfSalt);
        let _ = res.attributes.remove(&AttrId::KdfRounds);
        Ok(res)
    }

    fn encrypt(&self) -> Result<Multikey, Error> {
        let cipher = self.cipher.ok_or(CipherError::MissingCodec)?;

        let attr = self.mk.attr_view()?;
        if attr.is_encrypted() || !attr.is_secret_key() {
            return Err(
                CipherError::EncryptionFailed("key is encrypted already".to_string()).into(),
            );
        }

        let key = {
            let key = cipher.data_view()?.secret_bytes()?;
            if key.len() != self.key_length()? {
                return Err(CipherError::InvalidKey.into());
            }
            key
        };

        let plaintext = self.mk.data_view()?.key_bytes()?;

        let (mut capsule, mut kdf) = match cipher.codec {
            Codec::Mlkem512Pub => {
                let bytes = key.as_slice()[..ML512_PUBLIC_KEY_SIZE]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to convert secret key to public key".to_string(),
                        )
                    })?;
                let pk = EncapsulationKey::<MlKem512Params>::from_bytes(&bytes);
                let (capsule, mut sh) = pk.encapsulate(&mut rand_core_6::OsRng).map_err(|_| {
                    CipherError::EncryptionFailed("encapsulation error".to_string())
                })?;
                let mut shake = Shake256::default();
                shake.update(&capsule);
                shake.update(&sh);
                sh.zeroize();
                let data = shake.finalize_boxed(56);
                (capsule.to_vec(), data)
            }
            Codec::Mlkem768Pub => {
                let bytes = key.as_slice()[..ML768_PUBLIC_KEY_SIZE]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to convert secret key to public key".to_string(),
                        )
                    })?;
                let pk = EncapsulationKey::<MlKem768Params>::from_bytes(&bytes);
                let (capsule, mut sh) = pk.encapsulate(&mut rand_core_6::OsRng).map_err(|_| {
                    CipherError::EncryptionFailed("encapsulation error".to_string())
                })?;
                let mut shake = Shake256::default();
                shake.update(&capsule);
                shake.update(&sh);
                sh.zeroize();
                let data = shake.finalize_boxed(56);
                (capsule.to_vec(), data)
            }
            Codec::Mlkem1024Pub => {
                let bytes = key.as_slice()[..ML1024_PUBLIC_KEY_SIZE]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to convert secret key to public key".to_string(),
                        )
                    })?;
                let pk = EncapsulationKey::<MlKem1024Params>::from_bytes(&bytes);
                let (capsule, mut sh) = pk.encapsulate(&mut rand_core_6::OsRng).map_err(|_| {
                    CipherError::EncryptionFailed("encapsulation error".to_string())
                })?;
                let mut shake = Shake256::default();
                shake.update(&capsule);
                shake.update(&sh);
                sh.zeroize();
                let data = shake.finalize_boxed(56);
                (capsule.to_vec(), data)
            }
            _ => return Err(CipherError::UnsupportedCodec(cipher.codec).into()),
        };

        let mut nonce = XNonce::from_exact_iter(kdf[..24].iter().copied()).ok_or(
            CipherError::EncryptionFailed("invalid nonce bytes".to_string()),
        )?;
        let mut key = Key::from_exact_iter(kdf[24..].iter().copied()).ok_or(
            CipherError::EncryptionFailed("invalid key bytes".to_string()),
        )?;
        let chacha = XChaCha20Poly1305::new(&key);
        capsule.append(
            &mut chacha
                .encrypt(&nonce, &**plaintext)
                .map_err(|e| CipherError::EncryptionFailed(e.to_string()))?,
        );

        kdf.zeroize();
        nonce.zeroize();
        key.zeroize();

        let cattr = cipher.cipher_attr_view()?;
        let cipher_codec: Vec<u8> = cipher.codec.into();
        let key_length: Vec<u8> = Varuint(cattr.key_length()?).into();
        let is_encrypted: Vec<u8> = Varuint(true).into();

        let kattr = cipher.kdf_attr_view()?;
        let kdf_codec: Vec<u8> = kattr.kdf_codec()?.into();
        let salt = kattr.salt_bytes()?;
        let rounds: Vec<u8> = Varuint(kattr.rounds()?).into();

        let mut res = self.mk.clone();
        res.attributes
            .insert(AttrId::KeyIsEncrypted, is_encrypted.into());
        res.attributes
            .insert(AttrId::KeyData, Zeroizing::new(capsule));
        res.attributes
            .insert(AttrId::CipherCodec, cipher_codec.into());
        res.attributes
            .insert(AttrId::CipherKeyLen, key_length.into());
        res.attributes.insert(AttrId::KdfCodec, kdf_codec.into());
        res.attributes.insert(AttrId::KdfSalt, salt);
        res.attributes.insert(AttrId::KdfRounds, rounds.into());
        Ok(res)
    }
}
