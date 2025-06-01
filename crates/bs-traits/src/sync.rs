//! This module contains traits for synchronous operations.
use core::num::NonZeroUsize;

use crate::*;

/// Trait for types that can sign data
pub trait SyncSigner: Signer {
    /// Attempt to sign the data
    fn try_sign(&self, key: &Self::KeyPath, data: &[u8]) -> Result<Self::Signature, Self::Error>;

    /// Sign the data and return the signature
    ///
    /// # Panics
    ///
    /// This function will panic if the signing operation fails.
    fn sign(&self, key: &Self::KeyPath, data: &[u8]) -> Self::Signature {
        self.try_sign(key, data).expect("signing operation failed")
    }
}

pub type OneTimeSignFn<Sig, E> = Box<dyn FnOnce(&[u8]) -> Result<Sig, E>>;

pub type EphemeralSigningTuple<PK, Sig, E> = Result<(PK, OneTimeSignFn<Sig, E>), E>;

/// Trait for types that can prepare an ephemeral key for signing
pub trait SyncPrepareEphemeralSigning: Signer + EphemeralKey {
    /// The codec used for encoding/decoding keys
    type Codec;

    /// Prepares an ephemeral keypair, returning the public key and a one-time signing function
    fn prepare_ephemeral_signing(
        &self,
        codec: &Self::Codec, // Use concrete type to avoid associated type dependency
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> EphemeralSigningTuple<
        <Self as EphemeralKey>::PubKey,
        <Self as Signer>::Signature,
        <Self as Signer>::Error,
    >;
}

/// Trait for types that can verify signatures
pub trait SyncVerifier: Verifier {
    /// Verify that the provided signature for the given data is authentic
    fn verify(
        &self,
        key: &Self::Key,
        data: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Self::Error>;
}

/// Trait for types that can encrypt data
pub trait SyncEncryptor: Encryptor {
    /// Attempt to encrypt the plaintext
    fn try_encrypt(
        &self,
        key: &Self::Key,
        plaintext: &Self::Plaintext,
    ) -> Result<Self::Ciphertext, Self::Error>;

    /// Encrypt the plaintext
    fn encrypt(&self, key: &Self::Key, plaintext: &Self::Plaintext) -> Self::Ciphertext {
        self.try_encrypt(key, plaintext)
            .expect("encryption operation failed")
    }
}

/// Trait for types that can decrypt data
pub trait SyncDecryptor: Decryptor {
    /// Attempt to decrypt the ciphertext
    fn decrypt(
        &self,
        key: &Self::Key,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Self::Error>;
}

/// Trait for types that can split a secret into shares
pub trait SyncSecretSplitter: SecretSplitter {
    /// Split the secret into shares.
    ///
    /// Conditions for `split` to succeed:
    /// - Threshold must be less than or equal to limit.
    /// - Threshold must be greater than or equal to 2.
    fn split(
        &self,
        secret: &Self::Secret,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> Result<Self::Output, Self::Error>;

    /// Split the secret into shares with the given identifiers.
    /// The number of shares will be equal to the number of identifiers i.e. the `limit`.
    ///
    /// Conditions for `split_with_identifiers` to succeed:
    /// - Threshold must be less than or equal to the number of identifiers.
    /// - Threshold must be greater than or equal to 2.
    /// - Identifiers must be unique.
    /// - Identifiers must not be empty.
    fn split_with_identifiers(
        &self,
        secret: &Self::Secret,
        threshold: NonZeroUsize,
        identifiers: &[Self::Identifier],
    ) -> Result<Self::Output, Self::Error>;
}

/// Trait for types that can combine shares into a secret
pub trait SyncSecretCombiner: SecretCombiner {
    /// Combine the shares into a secret
    fn combine(
        &self,
        shares: &[(Self::Identifier, Self::Shares)],
    ) -> Result<Self::Secret, Self::Error>;
}

/// Trait for types that can retrieve a key
pub trait SyncGetKey: GetKey {
    /// Get the key
    fn get_key(
        &self,
        key_path: &Self::KeyPath,
        codec: &Self::Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> Result<Self::Key, Self::Error>;
}
