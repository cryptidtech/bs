// SPDX-License-Idnetifier: Apache-2.0
use crate::{
    error::{AttributesError, CipherError, KdfError},
    AttrId, AttrView, CipherAttrView, CipherView, DataView, Error, FingerprintView, KdfAttrView,
    Multikey, Views,
};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Nonce};
use multicodec::Codec;
use multihash::{mh, Multihash};
use multitrait::TryDecodeFrom;
use multiutil::Varuint;
use zeroize::Zeroizing;

use super::bcrypt::SALT_LENGTH;

pub const KEY_SIZE: usize = poly1305::KEY_SIZE;

/// Return the length of the [Nonce]
#[allow(dead_code)]
pub(crate) fn nonce_length() -> usize {
    Nonce::default().len()
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
            if let Ok((b, _)) = Varuint::<bool>::try_decode_from(v.as_slice()) {
                return b.to_inner();
            }
        }
        false
    }

    fn is_secret_key(&self) -> bool {
        true
    }

    fn is_public_key(&self) -> bool {
        false
    }

    fn is_secret_key_share(&self) -> bool {
        false
    }
}

impl DataView for View<'_> {
    /// return the ChaCha20 key bytes
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
        if self.is_encrypted() {
            return Err(AttributesError::EncryptedKey.into());
        }
        self.key_bytes()
    }
}

impl CipherAttrView for View<'_> {
    fn cipher_codec(&self) -> Result<Codec, Error> {
        Ok(Codec::Chacha20Poly1305)
    }

    fn nonce_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        // try to look up the salt in the multikey attributes
        let nonce = self
            .mk
            .attributes
            .get(&AttrId::CipherNonce)
            .ok_or(CipherError::MissingNonce)?;

        let nonce =
            Nonce::from_exact_iter(nonce.iter().copied()).ok_or(CipherError::InvalidNonce)?;

        Ok(nonce.to_vec().into())
    }

    fn key_length(&self) -> Result<usize, Error> {
        Ok(KEY_SIZE)
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
        let salt = self
            .mk
            .attributes
            .get(&AttrId::KdfSalt)
            .ok_or(KdfError::MissingSalt)?;
        if salt.len() != SALT_LENGTH {
            Err(KdfError::InvalidSaltLen.into())
        } else {
            Ok(salt.clone())
        }
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

impl CipherView for View<'_> {
    fn decrypt(&self) -> Result<Multikey, Error> {
        let cipher = self.cipher.ok_or(CipherError::MissingCodec)?;
        // make sure the viewed key is an encrypted secret key
        let attr = self.mk.attr_view()?;
        if !attr.is_encrypted() || !attr.is_secret_key() {
            return Err(CipherError::DecryptionFailed.into());
        }

        // get the nonce data from the passed-in Multikey
        let nonce = {
            let cattr = cipher.cipher_attr_view()?;
            cattr.nonce_bytes()?
        };

        // create the chacha nonce from the data
        let n = Nonce::from_exact_iter(nonce.iter().copied()).ok_or(CipherError::InvalidNonce)?;

        // get the key data from the passed-in Multikey
        let key = {
            let kd = cipher.data_view()?;
            let key = kd.secret_bytes()?;
            if key.len() != self.key_length()? {
                return Err(CipherError::InvalidKey.into());
            }
            key
        };

        // create the chacha key from the data
        let k =
            chacha20::Key::from_exact_iter(key.iter().copied()).ok_or(CipherError::InvalidKey)?;

        // get the encrypted key bytes from the viewed Multikey (self)
        let msg = {
            let attr = self.mk.data_view()?;
            attr.key_bytes()?
        };

        // // decrypt the key bytes
        // let dec = chacha20poly1305::open(msg.as_slice(), None, &n, &k)
        //     .map_err(|_| CipherError::DecryptionFailed)?;

        let mut chacha = ChaCha20::new(&k, &n);

        let mut dec = msg.clone();

        chacha.apply_keystream(&mut dec);

        // create a new Multikey from the viewed Multikey (self) with the
        // decrypted key and none of the kdf or cipher attributes
        let mut res = self.mk.clone();
        let _ = res.attributes.remove(&AttrId::KeyIsEncrypted);
        res.attributes.insert(AttrId::KeyData, dec);
        let _ = res.attributes.remove(&AttrId::CipherCodec);
        let _ = res.attributes.remove(&AttrId::CipherKeyLen);
        let _ = res.attributes.remove(&AttrId::CipherNonce);
        let _ = res.attributes.remove(&AttrId::KdfCodec);
        let _ = res.attributes.remove(&AttrId::KdfSalt);
        let _ = res.attributes.remove(&AttrId::KdfRounds);
        Ok(res)
    }

    fn encrypt(&self) -> Result<Multikey, Error> {
        let cipher = self.cipher.ok_or(CipherError::MissingCodec)?;
        // make sure the viewed key is not encrypted
        let attr = self.mk.attr_view()?;
        if attr.is_encrypted() {
            return Err(
                CipherError::EncryptionFailed("key is encrypted already".to_string()).into(),
            );
        }

        // get the nonce data from the passed-in Multikey
        let nonce = {
            let cattr = cipher.cipher_attr_view()?;
            cattr.nonce_bytes()?
        };

        let n = Nonce::from_exact_iter(nonce.iter().copied()).ok_or(CipherError::InvalidNonce)?;

        // get the key data from the passed-in Multikey
        let key = {
            let kd = cipher.data_view()?;
            let key = kd.secret_bytes()?;
            if key.len() != self.key_length()? {
                return Err(CipherError::InvalidKey.into());
            }
            key
        };

        let k =
            chacha20::Key::from_exact_iter(key.iter().copied()).ok_or(CipherError::InvalidKey)?;

        // get the secret bytes from the viewed Multikey
        let msg = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };

        let mut chacha = ChaCha20::new(&k, &n);

        let mut enc = msg.clone();

        // apply keystream (encrypt)
        chacha.apply_keystream(&mut enc);

        // prepare the cipher attributes
        let cattr = cipher.cipher_attr_view()?;
        let cipher_codec: Vec<u8> = cipher.codec.into();
        let key_length: Vec<u8> = Varuint(cattr.key_length()?).into();
        let is_encrypted: Vec<u8> = Varuint(true).into();

        // get a view on the kdf attributes
        let kattr = cipher.kdf_attr_view()?;
        let kdf_codec: Vec<u8> = kattr.kdf_codec()?.into();
        let salt = kattr.salt_bytes()?;
        let rounds: Vec<u8> = Varuint(kattr.rounds()?).into();

        // create a copy of the viewed Multikey (self) and add in the encrypted
        // key data as awell as the kdf and cipher attributes and data so that
        // the encrypted Multikey is self-describing about how it was encrypted
        let mut res = self.mk.clone();
        res.attributes
            .insert(AttrId::KeyIsEncrypted, is_encrypted.into());
        res.attributes.insert(AttrId::KeyData, enc);
        res.attributes
            .insert(AttrId::CipherCodec, cipher_codec.into());
        res.attributes
            .insert(AttrId::CipherKeyLen, key_length.into());
        res.attributes.insert(AttrId::CipherNonce, nonce.clone());
        res.attributes.insert(AttrId::KdfCodec, kdf_codec.into());
        res.attributes.insert(AttrId::KdfSalt, salt.clone());
        res.attributes.insert(AttrId::KdfRounds, rounds.into());
        Ok(res)
    }
}

impl FingerprintView for View<'_> {
    fn fingerprint(&self, codec: Codec) -> Result<Multihash, Error> {
        // get the key bytes
        let bytes = {
            let kd = self.mk.data_view()?;
            kd.key_bytes()?
        };
        // hash the key bytes using the given codec
        Ok(mh::Builder::new_from_bytes(codec, bytes)?.try_build()?)
    }
}
