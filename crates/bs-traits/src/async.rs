// SPDX-License-Identifier: FSL-1.1
//! This module provides traits for asynchronous operations
use crate::cond_send::{CondSend, CondSync};
use crate::*;
use std::future::Future;
use std::num::NonZeroUsize;

/// Trait for types that can sign data asynchronously
pub trait AsyncSigner: Signer {
    /// Attempt to sign the data asynchronously
    fn try_sign(
        &self,
        key: &Self::Key,
        data: &[u8],
    ) -> impl Future<Output = Result<Self::Signature, Self::Error>> + CondSend + '_;

    /// Sign the data asynchronously
    ///
    /// # Panics
    ///
    /// This function will panic if the signing operation fails.
    fn sign<'a>(
        &'a self,
        key: &'a Self::Key,
        data: &'a [u8],
    ) -> impl Future<Output = Self::Signature> + CondSend + 'a
    where
        Self: CondSync,
        Self::Key: CondSync,
    {
        async move {
            self.try_sign(key, data)
                .await
                .expect("signing operation failed")
        }
    }
}

/// Trait for types that can verify data asynchronously
pub trait AsyncVerifier: Verifier {
    /// Verify the data asynchronously
    fn verify(
        &self,
        key: &Self::Key,
        data: &[u8],
        signature: &Self::Signature,
    ) -> impl Future<Output = Result<(), Self::Error>> + CondSend + '_;
}

/// Trait for types that can encrypt data asynchronously
pub trait AsyncEncryptor: Encryptor {
    /// Attempt to encrypt the data asynchronously
    fn try_encrypt(
        &self,
        key: &Self::Key,
        plaintext: &Self::Plaintext,
    ) -> impl Future<Output = Result<Self::Ciphertext, Self::Error>> + CondSend + '_;

    /// Encrypt the data asynchronously
    ///
    /// # Panics
    ///
    /// This function will panic if the encryption operation fails.
    fn encrypt<'a>(
        &'a self,
        key: &'a Self::Key,
        plaintext: &'a Self::Plaintext,
    ) -> impl Future<Output = Self::Ciphertext> + CondSend + 'a
    where
        Self: CondSync,
        Self::Key: CondSync,
        Self::Plaintext: CondSync,
    {
        async move {
            self.try_encrypt(key, plaintext)
                .await
                .expect("encryption operation failed")
        }
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
    fn get_key(
        &self,
        key_path: &Self::KeyPath,
        codec: &Self::Codec,
        threshold: usize,
        limit: usize,
    ) -> impl Future<Output = Result<Self::Key, Self::Error>> + CondSend + '_;
}
