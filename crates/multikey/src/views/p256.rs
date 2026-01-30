// SPDX-License-Identifier: Apache-2.0
//! P-256 (NIST P-256 / secp256r1 / prime256v1) key view implementations
//!
//! This module provides full support for P-256 ECDSA signatures (ES256).
//! Primary use case: WebAuthn/passkey signature verification, but signing is also supported.
//!
//! Note: For WebAuthn, passkeys handle signing externally via authenticator hardware/software.
//! This implementation can be used for general P-256 ECDSA operations when needed.

use crate::{
    error::{AttributesError, CipherError, ConversionsError, KdfError, SignError, VerifyError},
    AttrId, AttrView, Builder, CipherAttrView, ConvView, DataView, Error, FingerprintView,
    KdfAttrView, Multikey, SignView, VerifyView, Views,
};

use multicodec::Codec;
use multihash::{mh, Multihash};
use multisig::{ms, Multisig, Views as SigViews};
use multitrait::TryDecodeFrom;
use multiutil::Varuint;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

/// The number of bytes in a P-256 secret key (scalar)
pub const SECRET_KEY_LENGTH: usize = 32;

/// The number of bytes in a compressed P-256 public key (SEC1 format)
#[allow(dead_code)]
pub const PUBLIC_KEY_COMPRESSED_LENGTH: usize = 33;

/// The number of bytes in an uncompressed P-256 public key (SEC1 format)
#[allow(dead_code)]
pub const PUBLIC_KEY_UNCOMPRESSED_LENGTH: usize = 65;

/// The number of bytes in a P-256 ECDSA signature (raw r||s format)
#[allow(dead_code)]
pub const SIGNATURE_LENGTH: usize = 64;

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
        self.mk.codec == Codec::P256Priv
    }

    fn is_public_key(&self) -> bool {
        self.mk.codec == Codec::P256Pub
    }

    fn is_secret_key_share(&self) -> bool {
        false // P-256 doesn't support threshold signatures natively
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
            // Convert to public key first, then fingerprint it
            let pk = self.to_public_key()?;
            let fp = pk.fingerprint_view()?;
            fp.fingerprint(codec)
        } else {
            // Hash the public key bytes directly
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

        // Create P-256 signing key from 32-byte scalar
        let bytes: [u8; SECRET_KEY_LENGTH] = secret_bytes.as_slice()[..SECRET_KEY_LENGTH]
            .try_into()
            .map_err(|_| {
                ConversionsError::SecretKeyFailure("P-256 secret key must be 32 bytes".to_string())
            })?;

        let signing_key = SigningKey::from_bytes(&bytes.into())
            .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;

        let verifying_key = signing_key.verifying_key();

        // Encode as compressed SEC1 (33 bytes: 0x02/0x03 + x-coordinate)
        let compressed = true;
        let encoded_point = verifying_key.to_encoded_point(compressed);
        let public_key_bytes = encoded_point.as_bytes();

        Builder::new(Codec::P256Pub)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&public_key_bytes)
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        use ssh_key::public::{EcdsaPublicKey, KeyData};

        let mut pk = self.mk.clone();
        if self.is_secret_key() {
            pk = self.to_public_key()?;
        }

        let key_bytes = {
            let kd = pk.data_view()?;
            kd.key_bytes()?
        };

        // Parse SEC1 encoded point (handles both compressed and uncompressed)
        let verifying_key = VerifyingKey::from_sec1_bytes(&key_bytes)
            .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;

        // Get uncompressed point (65 bytes: 0x04 || x || y)
        let compressed = false;
        let encoded_point = verifying_key.to_encoded_point(compressed);

        // SSH sec1::EncodedPoint expects the point WITHOUT the 0x04 prefix
        // It should be exactly 64 bytes (32 bytes x + 32 bytes y)
        let point_bytes = encoded_point.as_bytes();
        if point_bytes.len() != 65 || point_bytes[0] != 0x04 {
            return Err(ConversionsError::PublicKeyFailure(
                "Expected uncompressed point with 0x04 prefix".to_string(),
            )
            .into());
        }

        // Create the 64-byte array (x || y coordinates) without the 0x04 prefix
        let point_data: [u8; 64] = point_bytes[1..]
            .try_into()
            .map_err(|_| ConversionsError::PublicKeyFailure("Invalid point size".to_string()))?;

        // SSH expects a sec1::EncodedPoint, which we can create from the uncompressed bytes
        // The sec1::EncodedPoint::from_untagged_bytes expects the bytes without the tag
        let sec1_point =
            sec1::EncodedPoint::<sec1::consts::U32>::from_untagged_bytes(&point_data.into());

        let ecdsa_key = EcdsaPublicKey::NistP256(sec1_point);

        Ok(ssh_key::PublicKey::new(
            KeyData::Ecdsa(ecdsa_key),
            pk.comment,
        ))
    }

    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };

        let bytes: [u8; SECRET_KEY_LENGTH] = secret_bytes.as_slice()[..SECRET_KEY_LENGTH]
            .try_into()
            .map_err(|_| {
                ConversionsError::SecretKeyFailure("P-256 secret key must be 32 bytes".to_string())
            })?;

        let secret_key = SigningKey::from_bytes(&bytes.into())
            .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;

        let verifying_key = secret_key.verifying_key();

        // Get the public key point in uncompressed format (without 0x04 prefix)
        let encoded_point = verifying_key.to_encoded_point(false);
        let point_bytes = encoded_point.as_bytes();
        if point_bytes.len() != 65 || point_bytes[0] != 0x04 {
            return Err(ConversionsError::PublicKeyFailure(
                "Expected uncompressed point".to_string(),
            )
            .into());
        }

        // Create the public key bytes (64 bytes: x || y)
        let public_bytes: [u8; 64] = point_bytes[1..]
            .try_into()
            .map_err(|_| ConversionsError::PublicKeyFailure("Invalid point size".to_string()))?;

        // Create the SSH keypair structure
        // Convert to p256::SecretKey first, then to ssh_key types
        let p256_secret = p256::SecretKey::from_bytes(&bytes.into())
            .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;

        let private_key_bytes =
            ssh_key::private::EcdsaPrivateKey::<SECRET_KEY_LENGTH>::from(p256_secret);
        let public_key_point =
            sec1::EncodedPoint::<sec1::consts::U32>::from_untagged_bytes(&public_bytes.into());

        let keypair = ssh_key::private::EcdsaKeypair::NistP256 {
            private: private_key_bytes,
            public: public_key_point,
        };

        Ok(ssh_key::PrivateKey::new(
            ssh_key::private::KeypairData::Ecdsa(keypair),
            self.mk.comment.clone(),
        )?)
    }
}

impl SignView for View<'_> {
    /// Sign a message with P-256 ECDSA (ES256)
    ///
    /// Creates an ECDSA signature over the provided message.
    /// For WebAuthn use cases, passkeys typically handle signing externally,
    /// but this implementation supports general P-256 signing operations.
    fn sign(&self, msg: &[u8], combined: bool, _scheme: Option<u8>) -> Result<Multisig, Error> {
        // Get the secret key bytes
        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };

        // Create P-256 signing key from 32-byte scalar
        let bytes: [u8; SECRET_KEY_LENGTH] = secret_bytes.as_slice()[..SECRET_KEY_LENGTH]
            .try_into()
            .map_err(|_| {
                SignError::SigningFailed("P-256 secret key must be 32 bytes".to_string())
            })?;

        let signing_key = SigningKey::from_bytes(&bytes.into())
            .map_err(|e| SignError::SigningFailed(e.to_string()))?;

        let signature: Signature = signing_key.sign(msg);

        let mut builder =
            ms::Builder::new(Codec::Es256Msig).with_signature_bytes(&signature.to_bytes());

        if combined {
            builder = builder.with_message_bytes(&msg);
        }

        Ok(builder.try_build()?)
    }
}

impl VerifyView for View<'_> {
    /// Verify a P-256 ECDSA signature (ES256)
    ///
    /// This is the primary function for passkey support, as it verifies signatures
    /// created by external authenticators.
    fn verify(&self, multisig: &Multisig, msg: Option<&[u8]>) -> Result<(), Error> {
        let attr = self.mk.attr_view()?;
        let pubmk = if attr.is_secret_key() {
            let kc = self.mk.conv_view()?;
            kc.to_public_key()?
        } else {
            self.mk.clone()
        };

        let key_bytes = {
            let kd = pubmk.data_view()?;
            kd.key_bytes()?
        };

        // Create verifying key from SEC1-encoded public key
        let verifying_key = VerifyingKey::from_sec1_bytes(&key_bytes)
            .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;

        let sv = multisig.data_view()?;
        let sig_bytes = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;

        // Create signature from bytes (handles both DER and raw r||s formats)
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| VerifyError::BadSignature(e.to_string()))?;

        let msg = if let Some(msg) = msg {
            msg
        } else if !multisig.message.is_empty() {
            multisig.message.as_slice()
        } else {
            return Err(VerifyError::MissingMessage.into());
        };

        verifying_key
            .verify(msg, &signature)
            .map_err(|e| VerifyError::BadSignature(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Builder;
    use multicodec::Codec;
    use multiutil::CodecInfo;
    use rand_core_6::OsRng;
    use ssh_key::private::EcdsaKeypair;
    use ssh_key::private::KeypairData;
    use ssh_key::PrivateKey;

    fn create_test_keypair() -> Multikey {
        let mut rng = OsRng;
        Builder::new_from_random_bytes(Codec::P256Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap()
    }

    fn create_test_keypair_from_ssh() -> Multikey {
        let mut rng = OsRng;
        let keypair = EcdsaKeypair::random(&mut rng, ssh_key::EcdsaCurve::NistP256).unwrap();
        let private_key_ssh = PrivateKey::new(KeypairData::Ecdsa(keypair), "test").unwrap();
        Builder::new_from_ssh_private_key(&private_key_ssh)
            .unwrap()
            .try_build()
            .unwrap()
    }

    #[test]
    fn test_attr_view_secret_key() {
        let mk = create_test_keypair();
        let view = View::try_from(&mk).unwrap();

        assert!(!view.is_encrypted());
        assert!(view.is_secret_key());
        assert!(!view.is_public_key());
        assert!(!view.is_secret_key_share());
    }

    #[test]
    fn test_attr_view_public_key() {
        let mk = create_test_keypair();
        let pk = mk.conv_view().unwrap().to_public_key().unwrap();
        let view = View::try_from(&pk).unwrap();

        assert!(!view.is_encrypted());
        assert!(!view.is_secret_key());
        assert!(view.is_public_key());
        assert!(!view.is_secret_key_share());
    }

    #[test]
    fn test_data_view_key_bytes() {
        let mk = create_test_keypair();
        let view = View::try_from(&mk).unwrap();

        let key_bytes = view.key_bytes().unwrap();
        assert_eq!(key_bytes.len(), SECRET_KEY_LENGTH);
    }

    #[test]
    fn test_data_view_secret_bytes() {
        let mk = create_test_keypair();
        let view = View::try_from(&mk).unwrap();

        let secret_bytes = view.secret_bytes().unwrap();
        assert_eq!(secret_bytes.len(), SECRET_KEY_LENGTH);
    }

    #[test]
    fn test_data_view_secret_bytes_fails_for_public_key() {
        let mk = create_test_keypair();
        let pk = mk.conv_view().unwrap().to_public_key().unwrap();
        let view = View::try_from(&pk).unwrap();

        let result = view.secret_bytes();
        assert!(result.is_err());
    }

    #[test]
    fn test_to_public_key() {
        let mk = create_test_keypair();
        let view = View::try_from(&mk).unwrap();

        let pk = view.to_public_key().unwrap();
        assert_eq!(pk.codec(), Codec::P256Pub);

        let pk_view = View::try_from(&pk).unwrap();
        assert!(pk_view.is_public_key());
        assert!(!pk_view.is_secret_key());

        let key_bytes = pk_view.key_bytes().unwrap();
        assert_eq!(key_bytes.len(), PUBLIC_KEY_COMPRESSED_LENGTH);
    }

    #[test]
    fn test_to_public_key_is_deterministic() {
        let mk = create_test_keypair();
        let view = View::try_from(&mk).unwrap();

        let pk1 = view.to_public_key().unwrap();
        let pk2 = view.to_public_key().unwrap();

        let pk1_bytes = pk1.data_view().unwrap().key_bytes().unwrap();
        let pk2_bytes = pk2.data_view().unwrap().key_bytes().unwrap();

        assert_eq!(pk1_bytes.as_slice(), pk2_bytes.as_slice());
    }

    #[test]
    fn test_fingerprint_view_for_secret_key() {
        let mk = create_test_keypair();
        let view = View::try_from(&mk).unwrap();

        let fingerprint = view.fingerprint(Codec::Sha2256).unwrap();
        let digest: Vec<u8> = fingerprint.into();
        // Multihash includes codec prefix (2 bytes) + digest (32 bytes for SHA-256)
        assert!(digest.len() == 34, "Multihash should include digest bytes");
    }

    #[test]
    fn test_fingerprint_view_for_public_key() {
        let mk = create_test_keypair();
        let pk = mk.conv_view().unwrap().to_public_key().unwrap();
        let view = View::try_from(&pk).unwrap();

        let fingerprint = view.fingerprint(Codec::Sha2256).unwrap();
        let digest: Vec<u8> = fingerprint.into();
        // Multihash includes codec prefix (2 bytes) + digest (32 bytes for SHA-256)
        assert!(digest.len() >= 32, "Multihash should include digest bytes");
    }

    #[test]
    fn test_fingerprint_same_for_secret_and_public() {
        let mk = create_test_keypair();
        let pk = mk.conv_view().unwrap().to_public_key().unwrap();

        let sk_view = View::try_from(&mk).unwrap();
        let pk_view = View::try_from(&pk).unwrap();

        let sk_fp = sk_view.fingerprint(Codec::Sha2256).unwrap();
        let pk_fp = pk_view.fingerprint(Codec::Sha2256).unwrap();

        let sk_digest: Vec<u8> = sk_fp.into();
        let pk_digest: Vec<u8> = pk_fp.into();

        assert_eq!(sk_digest, pk_digest);
    }

    #[test]
    fn test_to_ssh_public_key() {
        let mk = create_test_keypair();
        let view = View::try_from(&mk).unwrap();

        let ssh_pub = view.to_ssh_public_key().unwrap();
        assert_eq!(
            ssh_pub.algorithm(),
            ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256
            }
        );
    }

    #[test]
    fn test_to_ssh_public_key_from_public_key() {
        let mk = create_test_keypair();
        let pk = mk.conv_view().unwrap().to_public_key().unwrap();
        let view = View::try_from(&pk).unwrap();

        let ssh_pub = view.to_ssh_public_key().unwrap();
        assert_eq!(
            ssh_pub.algorithm(),
            ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256
            }
        );
    }

    #[test]
    fn test_to_ssh_private_key() {
        let mk = create_test_keypair();
        let view = View::try_from(&mk).unwrap();

        let ssh_priv = view.to_ssh_private_key().unwrap();
        assert_eq!(
            ssh_priv.algorithm(),
            ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256
            }
        );
    }

    #[test]
    fn test_to_ssh_private_key_roundtrip() {
        // Create a key, convert to SSH, then back to Multikey
        // The reconstructed key should be able to produce the same public key
        let mk1 = create_test_keypair();
        let pk1 = mk1.conv_view().unwrap().to_public_key().unwrap();
        let pk1_bytes = pk1.data_view().unwrap().key_bytes().unwrap();

        let view = View::try_from(&mk1).unwrap();
        let ssh_priv = view.to_ssh_private_key().unwrap();

        // Convert back
        let mk2 = Builder::new_from_ssh_private_key(&ssh_priv)
            .unwrap()
            .try_build()
            .unwrap();
        let pk2 = mk2.conv_view().unwrap().to_public_key().unwrap();
        let pk2_bytes = pk2.data_view().unwrap().key_bytes().unwrap();

        assert_eq!(pk1_bytes.as_slice(), pk2_bytes.as_slice());
    }

    #[test]
    fn test_ssh_roundtrip_from_ssh_origin() {
        // Start with SSH key, convert to Multikey, back to SSH, back to Multikey
        let mk1 = create_test_keypair_from_ssh();
        let sk1_bytes = mk1.data_view().unwrap().secret_bytes().unwrap();

        // Convert to SSH
        let view = View::try_from(&mk1).unwrap();
        let ssh_priv = view.to_ssh_private_key().unwrap();

        // Convert back to Multikey
        let mk2 = Builder::new_from_ssh_private_key(&ssh_priv)
            .unwrap()
            .try_build()
            .unwrap();
        let sk2_bytes = mk2.data_view().unwrap().secret_bytes().unwrap();

        assert_eq!(sk1_bytes.as_slice(), sk2_bytes.as_slice());
    }

    #[test]
    fn test_sign_and_verify() {
        // Test that we can sign and verify using built-in signing
        let mk = create_test_keypair();
        let pk = mk.conv_view().unwrap().to_public_key().unwrap();

        let message = b"test message";

        // Sign using built-in signing
        let signature = mk.sign_view().unwrap().sign(message, false, None).unwrap();

        // Verify
        let result = pk.verify_view().unwrap().verify(&signature, Some(message));
        assert!(result.is_ok(), "Signature verification should succeed");
    }

    #[test]
    fn test_verify_view_with_valid_signature() {
        let mk = create_test_keypair();
        let pk = mk.conv_view().unwrap().to_public_key().unwrap();

        let message = b"test message to sign";

        // Sign using built-in signing
        let signature = mk.sign_view().unwrap().sign(message, false, None).unwrap();

        // Verify
        let view = View::try_from(&pk).unwrap();
        let result = view.verify(&signature, Some(message));

        assert!(result.is_ok(), "Signature verification should succeed");
    }

    #[test]
    fn test_verify_view_with_wrong_message() {
        let mk = create_test_keypair();
        let pk = mk.conv_view().unwrap().to_public_key().unwrap();

        let original_message = b"original message";
        let wrong_message = b"wrong message";

        // Sign the original message
        let signature = mk
            .sign_view()
            .unwrap()
            .sign(original_message, false, None)
            .unwrap();

        // Try to verify with wrong message
        let view = View::try_from(&pk).unwrap();
        let result = view.verify(&signature, Some(wrong_message));

        assert!(
            result.is_err(),
            "Verification should fail with wrong message"
        );
    }

    #[test]
    fn test_verify_view_with_combined_signature() {
        let mk = create_test_keypair();
        let pk = mk.conv_view().unwrap().to_public_key().unwrap();

        let message = b"combined signature test";

        // Create a combined signature (message embedded)
        let signature = mk.sign_view().unwrap().sign(message, true, None).unwrap();

        assert!(
            !signature.message.is_empty(),
            "Combined signature should contain message"
        );

        // Verify without providing message (it's in the signature)
        let view = View::try_from(&pk).unwrap();
        let result = view.verify(&signature, None);

        assert!(
            result.is_ok(),
            "Combined signature verification should succeed"
        );
    }

    #[test]
    fn test_verify_view_from_secret_key() {
        // Should be able to verify using a secret key (auto-converts to public)
        let mk = create_test_keypair();
        let message = b"test message";

        // Sign
        let signature = mk.sign_view().unwrap().sign(message, false, None).unwrap();

        // Verify using secret key directly
        let view = View::try_from(&mk).unwrap();
        let result = view.verify(&signature, Some(message));

        assert!(result.is_ok(), "Should verify from secret key");
    }

    #[test]
    fn test_verify_view_missing_message() {
        let mk = create_test_keypair();
        let pk = mk.conv_view().unwrap().to_public_key().unwrap();
        let message = b"test";

        // Create signature WITHOUT embedding message
        let signature = mk.sign_view().unwrap().sign(message, false, None).unwrap();
        assert!(
            signature.message.is_empty(),
            "Non-combined signature should not contain message"
        );

        // Try to verify without providing message
        let view = View::try_from(&pk).unwrap();
        let result = view.verify(&signature, None);

        assert!(result.is_err(), "Should fail when message is missing");
    }
}
