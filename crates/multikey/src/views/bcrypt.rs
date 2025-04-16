// SPDX-License-Idnetifier: Apache-2.0
use crate::{error::KdfError, AttrId, Error, KdfAttrView, KdfView, Multikey, Views};
use multicodec::Codec;
use multiutil::Varuint;
use zeroize::Zeroizing;

/// constants for Bcrypt
pub const SALT_LENGTH: usize = 32;

pub(crate) struct View<'a> {
    mk: &'a Multikey,
    kdf: Option<&'a Multikey>,
}

impl<'a> View<'a> {
    pub fn new(mk: &'a Multikey, kdf: &'a Multikey) -> Self {
        Self { mk, kdf: Some(kdf) }
    }
}

impl<'a> TryFrom<&'a Multikey> for View<'a> {
    type Error = Error;

    fn try_from(mk: &'a Multikey) -> Result<Self, Self::Error> {
        Ok(Self { mk, kdf: None })
    }
}

impl KdfView for View<'_> {
    /// this takes the kdf attributes and data from the passed-in Multikey and
    /// generates a new Multikey by copying the viewed Multikey (self) and
    /// storing the derived key and attributes in the new Multikey
    fn derive_key(&self, passphrase: &[u8]) -> Result<Multikey, Error> {
        let kdf = self.kdf.ok_or(KdfError::MissingCodec)?;

        // get the salt data and rounds attribute
        let (salt, rounds) = {
            let kattr = kdf.kdf_attr_view()?;
            (kattr.salt_bytes()?, kattr.rounds()?)
        };

        // get the key length from the viewed Multikey
        let key_length = {
            let cattr = self.mk.cipher_attr_view()?;
            
            cattr.key_length()?
        };

        // heap allocate a buffer to receive the derived key
        let mut key: Zeroizing<Vec<u8>> = vec![0; key_length].into();

        // derive the key
        bcrypt_pbkdf::bcrypt_pbkdf(
            passphrase,
            &salt,
            rounds as u32,
            key.as_mut_slice(),
        )
        .map_err(KdfError::Bcrypt)?;

        // prepare the attributes
        let kdf_codec: Vec<u8> = kdf.codec.into();
        let rounds: Vec<u8> = Varuint(rounds).into();

        // create a new Multikey from the viewed Multikey (self) and store the
        // kdf parameters along with the derived key
        let mut res = self.mk.clone();
        res.attributes.insert(AttrId::KeyData, key.clone());
        let _ = res.attributes.remove(&AttrId::KeyIsEncrypted);
        res.attributes.insert(AttrId::KdfCodec, kdf_codec.into());
        res.attributes.insert(AttrId::KdfSalt, salt.clone());
        res.attributes.insert(AttrId::KdfRounds, rounds.into());
        Ok(res)
    }
}

impl KdfAttrView for View<'_> {
    fn kdf_codec(&self) -> Result<Codec, Error> {
        Ok(Codec::BcryptPbkdf)
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
