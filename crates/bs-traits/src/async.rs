// SPDX-License-Identifier: FSL-1.1

use crate::cond_send::{CondSend, CondSync};
use crate::*;
use std::error::Error as StdError;
use std::future::Future;
use std::num::NonZeroUsize;

/// Trait for types that can sign data asynchronously
pub trait AsyncSigner: Signer {
    /// Error type for signing operations
    type Error: StdError + 'static;

    /// Attempt to sign the data asynchronously
    fn try_sign_async(
        &self,
        key: &Self::Key,
        data: &[u8],
    ) -> impl Future<Output = Result<Self::Signature, Self::Error>> + CondSend + '_;

    /// Sign the data asynchronously
    ///
    /// # Panics
    ///
    /// This function will panic if the signing operation fails.
    fn sign_async<'a>(
        &'a self,
        key: &'a Self::Key,
        data: &'a [u8],
    ) -> impl Future<Output = Self::Signature> + CondSend + 'a
    where
        Self: CondSync,
        Self::Key: CondSync,
    {
        async move {
            self.try_sign_async(key, data)
                .await
                .expect("signing operation failed")
        }
    }
}

/// Trait for types that can verify data asynchronously
pub trait AsyncVerifier: Verifier {
    /// Error type for verification operations
    type Error: StdError + 'static;

    /// Verify the data asynchronously
    fn verify_async(
        &self,
        key: &Self::Key,
        data: &[u8],
        signature: &Self::Signature,
    ) -> impl Future<Output = Result<(), Self::Error>> + CondSend + '_;
}

/// Trait for types that can encrypt data asynchronously
pub trait AsyncEncryptor: Encryptor {
    /// Error type for encryption operations
    type Error: StdError + 'static;

    /// Attempt to encrypt the data asynchronously
    fn try_encrypt_async(
        &self,
        key: &Self::Key,
        plaintext: &Self::Plaintext,
    ) -> impl Future<Output = Result<Self::Ciphertext, Self::Error>> + CondSend + '_;

    /// Encrypt the data asynchronously
    ///
    /// # Panics
    ///
    /// This function will panic if the encryption operation fails.
    fn encrypt_async<'a>(
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
            self.try_encrypt_async(key, plaintext)
                .await
                .expect("encryption operation failed")
        }
    }
}

/// Trait for types that can decrypt data asynchronously
pub trait AsyncDecryptor: Decryptor {
    /// Error type for decryption operations
    type Error: StdError + 'static;

    /// Decrypt the data asynchronously
    fn decrypt_async(
        &self,
        key: &Self::Key,
        ciphertext: &Self::Ciphertext,
    ) -> impl Future<Output = Result<Self::Plaintext, Self::Error>> + CondSend + '_;
}

/// Trait for types that can split a secret into shares asynchronously
pub trait AsyncSecretSplitter: SecretSplitter {
    /// Error type for secret splitting operations
    type Error: StdError + 'static;

    /// Split the secret into shares asynchronously
    fn split_async(
        &self,
        secret: &Self::Secret,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + CondSend + '_;

    /// Split the secret into shares with the given identifiers asynchronously
    fn split_with_identifiers_async(
        &self,
        secret: &Self::Secret,
        threshold: NonZeroUsize,
        identifiers: &[Self::Identifier],
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + CondSend + '_;
}

/// Trait for types that can combine shares into a secret asynchronously
pub trait AsyncSecretCombiner: SecretCombiner {
    /// Error type for secret combining operations
    type Error: StdError + 'static;

    /// Combine the shares into a secret asynchronously
    fn combine_async(
        &self,
        shares: &[(Self::Identifier, Self::Shares)],
    ) -> impl Future<Output = Result<Self::Secret, Self::Error>> + CondSend + '_;
}

/// Trait for types that can get a key asynchronously
pub trait AsyncGetKey: GetKey {
    /// Error type for key retrieval operations
    type Error: StdError + 'static;

    /// Get the key asynchronously
    fn get_key_async(
        &self,
        key_path: &Self::KeyPath,
        codec: &Self::Codec,
        threshold: usize,
        limit: usize,
    ) -> impl Future<Output = Result<Self::Key, Self::Error>> + CondSend + '_;
}
