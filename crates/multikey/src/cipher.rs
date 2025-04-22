// SPDX-License-Idnetifier: Apache-2.0
use crate::{
    error::CipherError,
    mk::Attributes,
    views::{chacha20, mlkem},
    AttrId, Error, Multikey,
};
use multicodec::Codec;
use multiutil::Varuint;
use tracing::info;
use zeroize::Zeroizing;

/// the list of cipher codecs
pub const CIPHER_CODECS: [Codec; 4] = [
    Codec::Chacha20Poly1305,
    Codec::Mlkem512Priv,
    Codec::Mlkem768Priv,
    Codec::Mlkem1024Priv,
];

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
            info!("setting key length: {}", v.len());
            self.key_length = Some(v.clone());
        }
        // try to look up the nonce in the multikey attributes
        if let Some(v) = mk.attributes.get(&AttrId::CipherNonce) {
            self.nonce = Some(v.clone());
        }
        Ok(self)
    }

    /// add in the nonce for the cipher
    pub fn with_nonce(mut self, nonce: &impl AsRef<[u8]>) -> Result<Self, Error> {
        let n: Zeroizing<Vec<u8>> = Zeroizing::new(nonce.as_ref().to_vec());
        match self.codec {
            Codec::Chacha20Poly1305 => {
                if n.len() != chacha20::nonce_length(self.codec)? {
                    info!(
                        "nonce length: {}, expected: {}",
                        n.len(),
                        chacha20::nonce_length(self.codec)?
                    );
                    return Err(CipherError::InvalidNonceLen.into());
                }
            }
            Codec::Mlkem512Priv | Codec::Mlkem768Priv | Codec::Mlkem1024Priv => {
                if n.len() != mlkem::nonce_length(self.codec)? {
                    info!(
                        "nonce length: {}, expected: {}",
                        n.len(),
                        chacha20::nonce_length(self.codec)?
                    );
                    return Err(CipherError::InvalidNonceLen.into());
                }
            }
            _ => return Err(CipherError::UnsupportedCodec(self.codec).into()),
        }

        self.nonce = Some(n);
        Ok(self)
    }

    /// add a random nonce for cipher
    pub fn with_random_nonce(
        mut self,
        rng: &mut impl rand_core_6::CryptoRngCore,
    ) -> Result<Self, Error> {
        let len = match self.codec {
            Codec::Chacha20Poly1305 => chacha20::nonce_length(self.codec)?,
            Codec::Mlkem512Priv | Codec::Mlkem768Priv | Codec::Mlkem1024Priv => {
                mlkem::nonce_length(self.codec)?
            }
            _ => return Err(CipherError::UnsupportedCodec(self.codec).into()),
        };
        // heap allocate a buffer to receive the random nonce
        let mut buf: Zeroizing<Vec<u8>> = vec![0; len].into();
        rng.fill_bytes(buf.as_mut_slice());
        self.nonce = Some(buf);
        Ok(self)
    }

    /// build a key using key bytes
    pub fn try_build(self) -> Result<Multikey, Error> {
        let codec = self.codec;
        let comment = String::default();

        // add the cipher attributes
        let mut attributes = Attributes::new();
        if let Some(key_length) = self.key_length {
            attributes.insert(AttrId::CipherKeyLen, key_length);
        } else {
            let len = match codec {
                Codec::Chacha20Poly1305 => chacha20::key_length(codec)?,
                Codec::Mlkem512Priv | Codec::Mlkem768Priv | Codec::Mlkem1024Priv => {
                    mlkem::key_length(codec)?
                }
                _ => return Err(CipherError::UnsupportedCodec(self.codec).into()),
            };
            let key_length: Vec<u8> = Varuint(len).into();
            attributes.insert(AttrId::CipherKeyLen, key_length.into());
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
    use test_log::test;
    use tracing::{info, span, Level};

    use super::*;
    use crate::{kdf, mk, Views};

    #[test]
    fn test_keygen() {
        let _s = span!(Level::INFO, "test_keygen").entered();
        for codec in CIPHER_CODECS {
            let mut rng = StdRng::from_os_rng();
            let ciphermk = Builder::new(codec)
                .with_random_nonce(&mut rng)
                .unwrap()
                .try_build()
                .unwrap();

            let nonce = ciphermk.cipher_attr_view().unwrap().nonce_bytes().unwrap();
            info!("codec: {codec}, nonce: {}", hex::encode(nonce));
        }
    }

    #[test]
    fn test_chacha20() {
        let _s = span!(Level::INFO, "test_chacha20").entered();
        let salt = hex::decode("8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682")
            .unwrap();
        // create a kdf multikey
        let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
            .with_rounds(10)
            .with_salt(&salt)
            .try_build()
            .unwrap();

        // ChaCha needs 12 bytes of nonce iaw RFC8439
        let nonce = hex::decode("c6691d95f44e18f4cff311e3781eb2fc744de398585a94a3").unwrap();

        // create a cipher multikey
        let ciphermk = Builder::new(Codec::Chacha20Poly1305)
            .with_nonce(&nonce)
            .unwrap()
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
