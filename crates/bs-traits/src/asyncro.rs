// SPDX-License-Identifier: FSL-1.1
//! This module provides traits for asynchronous operations
use crate::cond_send::CondSend;
use crate::sync::EphemeralSigningTuple;
use crate::*;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;

// Helper trait that combines Future with CondSend
pub trait CondSendFuture<T>: Future<Output = T> + crate::cond_send::CondSend {}

// Blanket implementation for all types that implement both traits
impl<F, T> CondSendFuture<T> for F where F: Future<Output = T> + crate::cond_send::CondSend {}

// Type aliases for common return types
pub type BoxFuture<'a, T> = Pin<Box<dyn CondSendFuture<T> + 'a>>;

// Specific aliases for different trait return types
pub type SignerFuture<'a, S, E> = BoxFuture<'a, Result<S, E>>;
pub type GetKeyFuture<'a, K, E> = BoxFuture<'a, Result<K, E>>;
pub type VerifierFuture<'a, E> = BoxFuture<'a, Result<(), E>>;
pub type EncryptorFuture<'a, C, E> = BoxFuture<'a, Result<C, E>>;
pub type DecryptorFuture<'a, P, E> = BoxFuture<'a, Result<P, E>>;
pub type SecretSplitterFuture<'a, O, E> = BoxFuture<'a, Result<O, E>>;
pub type SecretCombinerFuture<'a, S, E> = BoxFuture<'a, Result<S, E>>;

/// Trait for types that can sign data asynchronously
pub trait AsyncSigner: Signer {
    /// Attempt to sign the data asynchronously
    fn try_sign<'a>(
        &'a self,
        key: &'a Self::KeyPath,
        data: &'a [u8],
    ) -> SignerFuture<'a, Self::Signature, Self::Error>;

    /// Sign the data asynchronously, unchedked.
    ///
    /// # Dyn Compatibility
    ///
    /// This function is not compatible with `dyn` trait objects
    ///
    /// # Panics
    ///
    /// This function will panic if the signing operation fails.
    #[cfg(not(feature = "dyn-compatible"))]
    fn sign<'a>(
        &'a self,
        key: &'a Self::KeyPath,
        data: &'a [u8],
    ) -> Pin<Box<dyn CondSendFuture<Self::Signature> + 'a>>
    where
        Self: CondSync,
        Self::KeyPath: CondSync,
    {
        Box::pin(async move {
            self.try_sign(key, data)
                .await
                .expect("signing operation failed")
        })
    }
}

/// Trait for types that can verify data asynchronously
pub trait AsyncVerifier: Verifier {
    fn verify<'a>(
        &'a self,
        key: &'a Self::Key,
        data: &'a [u8],
        signature: &'a Self::Signature,
    ) -> Pin<Box<dyn CondSendFuture<Result<bool, Self::Error>> + 'a>>;
}

pub trait AsyncEncryptor: Encryptor {
    fn try_encrypt<'a>(
        &'a self,
        key: &'a Self::Key,
        plaintext: &'a Self::Plaintext,
    ) -> EncryptorFuture<'a, Self::Ciphertext, Self::Error>;

    /// Encrypt the data asynchronously, unchecked.
    ///
    /// # Dyn Compatibility
    /// This function is not compatible with `dyn` trait objects
    ///
    /// # Panics
    /// This function will panic if the encryption operation fails.
    #[cfg(not(feature = "dyn-compatible"))]
    fn encrypt<'a>(
        &'a self,
        key: &'a Self::Key,
        plaintext: &'a Self::Plaintext,
    ) -> Pin<Box<dyn CondSendFuture<Self::Ciphertext> + 'a>>
    where
        Self: CondSync,
        Self::Key: CondSync,
        Self::Plaintext: CondSync,
    {
        Box::pin(async move {
            self.try_encrypt(key, plaintext)
                .await
                .expect("encryption operation failed")
        })
    }
}
/// Trait for types that can decrypt data asynchronously
pub trait AsyncDecryptor: Decryptor {
    /// Decrypt the data asynchronously
    fn decrypt(
        &self,
        key: &Self::Key,
        ciphertext: &Self::Ciphertext,
    ) -> impl Future<Output = Result<Self::Plaintext, Self::Error>> + CondSend + '_;
}

/// Trait for types that can split a secret into shares asynchronously
pub trait AsyncSecretSplitter: SecretSplitter {
    /// Split the secret into shares asynchronously
    ///
    /// Conditions for `split` to succeed:
    /// - Threshold must be less than or equal to limit.
    /// - Threshold must be greater than or equal to 2.
    fn split(
        &self,
        secret: &Self::Secret,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + CondSend + '_;

    /// Split the secret into shares with the given identifiers asynchronously
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
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + CondSend + '_;
}

/// Trait for types that can combine shares into a secret asynchronously
pub trait AsyncSecretCombiner: SecretCombiner {
    /// Combine the shares into a secret asynchronously
    fn combine(
        &self,
        shares: &[(Self::Identifier, Self::Shares)],
    ) -> impl Future<Output = Result<Self::Secret, Self::Error>> + CondSend + '_;
}

/// Trait for types that can get a key asynchronously
pub trait AsyncGetKey: GetKey {
    /// Get the key asynchronously
    fn get_key<'a>(
        &'a self,
        key_path: &'a Self::KeyPath,
        codec: &'a Self::Codec,
        threshold: usize,
        limit: usize,
    ) -> Result<GetKeyFuture<'a, Self::Key, Self::Error>, Self::Error>;
}

/// An async version of KeyManager
pub trait AsyncKeyManager<E>: GetKey + Send + Sync {
    fn get_key<'a>(
        &'a self,
        key_path: &'a Self::KeyPath,
        codec: &'a Self::Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> BoxFuture<'a, Result<Self::Key, E>>;
}

/// An async version of MultiSigner, including ephemeral signing
pub trait AsyncMultiSigner<S, E>:
    AsyncSigner<Signature = S, Error = E> + EphemeralKey + GetKey
where
    S: Send,
    E: Send,
{
    fn prepare_ephemeral_signing<'a>(
        &'a self,
        codec: &'a Self::Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> BoxFuture<'a, EphemeralSigningTuple<Self::PubKey, S, E>>;
}
