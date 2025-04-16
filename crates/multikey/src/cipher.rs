// SPDX-License-Idnetifier: Apache-2.0
use crate::{mk::Attributes, AttrId, Error, Multikey};
use multicodec::Codec;
use zeroize::Zeroizing;

/// Builder for creating a Multikey intended for encryption/decryption of other
/// Multikeys
#[derive(Clone, Debug, Default)]
pub struct Builder {
    codec: Codec,
    key_length: Option<Zeroizing<Vec<u8>>>,
    nonce: Option<Zeroizing<Vec<u8>>>,
}

impl Builder {
    /// create a new builder with the codec
    pub fn new(codec: Codec) -> Self {
        Builder {
            codec,
            ..Default::default()
        }
    }

    /// initialize from a multikey with cipher attributes in it
    pub fn try_from_multikey(mut self, mk: &Multikey) -> Result<Self, Error> {
        // try to look up the cipher codec in the multikey attributes
        if let Some(v) = mk.attributes.get(&AttrId::CipherCodec) {
            if let Ok(codec) = Codec::try_from(v.as_slice()) {
                self.codec = codec;
            }
        }
        // try to look up the key_length in the multikey attributes
        if let Some(v) = mk.attributes.get(&AttrId::CipherKeyLen) {
            self.key_length = Some(v.clone());
        }
        // try to look up the nonce in the multikey attributes
        if let Some(v) = mk.attributes.get(&AttrId::CipherNonce) {
            self.nonce = Some(v.clone());
        }
        Ok(self)
    }

    /// add in the nonce for the cipher
    pub fn with_nonce(mut self, nonce: &impl AsRef<[u8]>) -> Self {
        let n: Vec<u8> = nonce.as_ref().into();
        self.nonce = Some(n.into());
        self
    }

    /// add a random nonce for cipher
    pub fn with_random_nonce(
        mut self,
        len: usize,
        rng: &mut impl rand_core_6::CryptoRngCore,
    ) -> Self {
        // heap allocate a buffer to receive the random nonce
        let mut buf: Zeroizing<Vec<u8>> = vec![0; len].into();
        rng.fill_bytes(buf.as_mut_slice());
        self.nonce = Some(buf);
        self
    }

    /// build a key using key bytes
    pub fn try_build(self) -> Result<Multikey, Error> {
        let codec = self.codec;
        let comment = String::default();

        // add the cipher attributes
        let mut attributes = Attributes::new();
        if let Some(key_length) = self.key_length {
            attributes.insert(AttrId::CipherKeyLen, key_length);
        }
        if let Some(nonce) = self.nonce {
            attributes.insert(AttrId::CipherNonce, nonce);
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
    use rng::StdRng;

    use super::*;
    use crate::{kdf, mk, Views};

    #[test]
    fn test_chacha20() {
        let salt = hex::decode("8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682")
            .unwrap();
        // create a kdf multikey
        let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
            .with_rounds(10)
            .with_salt(&salt)
            .try_build()
            .unwrap();

        // ChaCha needs 12 bytes of nonce iaw RFC8439
        let nonce = hex::decode("00b61a43d4d1e8d700b61a43").unwrap();
        // create a cipher multikey
        let ciphermk = Builder::new(Codec::Chacha20Poly1305)
            .with_nonce(&nonce)
            .try_build()
            .unwrap();

        // get the kdf view on the kdf multikey
        let kdf = ciphermk.kdf_view(&kdfmk).unwrap();

        // derive a key for the cipher multikey to use
        let ciphermk = kdf
            .derive_key(b"for great justice, move every zig!")
            .unwrap();

        // generate a random secret key
        let mut rng = StdRng::from_os_rng();
        let mk = mk::Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();

        // get the cipher view on the multikey
        let cipher = mk.cipher_view(&ciphermk).unwrap();

        // encrypt the secret key
        let mk = cipher.encrypt().unwrap();

        // make sure all of the attributes are right
        let attr = mk.attr_view().unwrap();
        assert!(attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_err());
        let cattr = mk.cipher_attr_view().unwrap();
        assert_eq!(Codec::Chacha20Poly1305, cattr.cipher_codec().unwrap());
        assert!(cattr.nonce_bytes().is_ok());
        assert_eq!(32, cattr.key_length().unwrap());
        let kattr = mk.kdf_attr_view().unwrap();
        assert_eq!(Codec::BcryptPbkdf, kattr.kdf_codec().unwrap());
    }
}
