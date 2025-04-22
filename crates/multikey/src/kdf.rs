// SPDX-License-Idnetifier: Apache-2.0
use crate::{mk::Attributes, AttrId, Error, Multikey};
use multicodec::Codec;
use multiutil::Varuint;
use zeroize::Zeroizing;

/// Multikey builder constructs kdf multikeys.
#[derive(Clone, Debug, Default)]
pub struct Builder {
    codec: Codec,
    salt: Option<Zeroizing<Vec<u8>>>,
    rounds: Option<Zeroizing<Vec<u8>>>,
}

impl Builder {
    /// create a new multikey with the given codec
    pub fn new(codec: Codec) -> Self {
        Builder {
            codec,
            ..Default::default()
        }
    }

    /// initialize from a multikey with kdf attributes in it
    pub fn try_from_multikey(mut self, mk: &Multikey) -> Result<Self, Error> {
        // try to look up the kdf codec in the multikey attributes
        if let Some(v) = mk.attributes.get(&AttrId::KdfCodec) {
            if let Ok(codec) = Codec::try_from(v.as_slice()) {
                self.codec = codec;
            }
        }
        // try to look up the salt in the multikey attributes
        if let Some(v) = mk.attributes.get(&AttrId::KdfSalt) {
            self.salt = Some(v.clone());
        }
        // try to look up the rounds in the multikey attributes
        if let Some(v) = mk.attributes.get(&AttrId::KdfRounds) {
            self.rounds = Some(v.clone());
        }
        Ok(self)
    }

    /// add in the salt bytes for the kdf
    pub fn with_salt(mut self, salt: &impl AsRef<[u8]>) -> Self {
        let s: Vec<u8> = salt.as_ref().into();
        self.salt = Some(s.into());
        self
    }

    /// add a random salt for the kdf
    pub fn with_random_salt(
        mut self,
        len: usize,
        rng: &mut impl rand_core_6::CryptoRngCore,
    ) -> Self {
        // heap allocate a buffer to receive the random salt
        let mut buf: Zeroizing<Vec<u8>> = vec![0; len].into();
        rng.fill_bytes(buf.as_mut_slice());
        self.salt = Some(buf);
        self
    }

    /// add in the rounds
    pub fn with_rounds(mut self, rounds: usize) -> Self {
        let r: Vec<u8> = Varuint(rounds).into();
        self.rounds = Some(r.into());
        self
    }

    /// build a key using key bytes
    pub fn try_build(self) -> Result<Multikey, Error> {
        let codec = self.codec;
        let comment = String::default();

        // add the kdf attributes
        let mut attributes = Attributes::new();
        if let Some(salt) = self.salt {
            attributes.insert(AttrId::KdfSalt, salt);
        }
        if let Some(rounds) = self.rounds {
            attributes.insert(AttrId::KdfRounds, rounds);
        }

        Ok(Multikey {
            codec,
            comment,
            attributes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cipher, Views};

    #[test]
    fn test_bcrypt() {
        let salt = hex::decode("8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682")
            .unwrap();
        let kdfmk = Builder::new(Codec::BcryptPbkdf)
            .with_rounds(10)
            .with_salt(&salt)
            .try_build()
            .unwrap();

        let nonce = hex::decode("c6691d95f44e18f4cff311e3781eb2fc744de398585a94a3").unwrap();
        let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
            .with_nonce(&nonce)
            .unwrap()
            .try_build()
            .unwrap();

        // get the kdf view
        let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
        // derive a key from the passphrase and add it to the cipher multikey
        let ciphermk = kdf
            .derive_key(b"for great justice, move every zig!")
            .unwrap();

        let kattr = ciphermk.kdf_attr_view().unwrap();
        assert_eq!(Codec::BcryptPbkdf, kattr.kdf_codec().unwrap());
        assert_eq!(salt, kattr.salt_bytes().unwrap().to_vec());
        assert_eq!(10, kattr.rounds().unwrap());

        let kd = ciphermk.data_view().unwrap();
        assert_eq!(
            vec![
                119, 109, 13, 221, 140, 26, 88, 179, 135, 17, 119, 25, 176, 99, 5, 2, 203, 25, 82,
                16, 161, 246, 176, 139, 8, 101, 174, 7, 240, 67, 237, 107
            ],
            kd.secret_bytes().unwrap().to_vec()
        );
    }
}
