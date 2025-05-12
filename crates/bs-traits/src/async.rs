// SPDX-License-Identifier: FSL-1.1

use crate::*;
use std::{future::Future, num::NonZeroUsize};

/// Trait for types that can sign data asynchronously
pub trait AsyncSigner: Signer {
    /// Attempt to sign the data asynchronously
    fn try_sign_async<'a>(
        &'a self,
        key: &'a Self::Key,
        data: &'a [u8],
    ) -> impl Future<Output = Result<Self::Signature, Error>> + 'a;

    /// Sign the data asynchronously
    fn sign_async<'a>(
        &'a self,
        key: &'a Self::Key,
        data: &'a [u8],
    ) -> impl Future<Output = Self::Signature> + 'a {
        async move {
            self.try_sign_async(key, data)
                .await
                .expect("signing operation failed")
        }
    }
}

/// Trait for types that can verify data asynchronously
pub trait AsyncVerifier: Verifier {
    /// Verify the data asynchronously
    fn verify_async<'a>(
        &'a self,
        key: &'a Self::Key,
        data: &'a [u8],
        signature: &'a Self::Signature,
    ) -> impl Future<Output = Result<(), Error>> + 'a;
}

/// Trait for types that can encrypt data asynchronously
pub trait AsyncEncryptor: Encryptor {
    /// Attempt to encrypt the data asynchronously
    fn try_encrypt_async<'a>(
        &'a self,
        key: &'a Self::Key,
        plaintext: &'a Self::Plaintext,
    ) -> impl Future<Output = Result<Self::Ciphertext, Error>> + 'a;

    /// Encrypt the data asynchronously
    fn encrypt_async<'a>(
        &'a self,
        key: &'a Self::Key,
        plaintext: &'a Self::Plaintext,
    ) -> impl Future<Output = Self::Ciphertext> + 'a {
        async move {
            self.try_encrypt_async(key, plaintext)
                .await
                .expect("encryption operation failed")
        }
    }
}

/// Trait for types that can decrypt data asynchronously
pub trait AsyncDecryptor: Decryptor {
    /// Decrypt the data asynchronously
    fn decrypt_async<'a>(
        &'a self,
        key: &'a Self::Key,
        ciphertext: &'a Self::Ciphertext,
    ) -> impl Future<Output = Result<Self::Plaintext, Error>> + 'a;
}

/// Trait for types that can split a secret into shares asynchronously
pub trait AsyncSecretSplitter: SecretSplitter {
    /// Split the secret into shares asynchronously
    fn split_async<'a>(
        &'a self,
        secret: &'a Self::Secret,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> impl Future<Output = Result<Self::Output, Error>> + 'a;

    /// Split the secret into shares with the given identifiers asynchronously
    fn split_with_identifiers_async<'a>(
        &'a self,
        secret: &'a Self::Secret,
        threshold: NonZeroUsize,
        identifiers: &'a [Self::Identifier],
    ) -> impl Future<Output = Result<Self::Output, Error>> + 'a;
}

/// Trait for types that can combine shares into a secret asynchronously
pub trait AsyncSecretCombiner: SecretCombiner {
    /// Combine the shares into a secret asynchronously
    fn combine_async<'a>(
        &'a self,
        shares: &'a [(Self::Identifier, Self::Shares)],
    ) -> impl Future<Output = Result<Self::Secret, Error>> + 'a;
}

/// Trait for types that can get a key asynchronously
pub trait AsyncGetKey: GetKey {
    /// Get the key asynchronously
    fn get_key_async<'a>(
        &'a self,
        key_path: &'a Self::KeyPath,
        codec: &'a Self::Codec,
        threshold: usize,
        limit: usize,
    ) -> impl Future<Output = Result<Self::Key, Error>> + 'a;
}
