// SPDX-License-Identifier: FSL-1.1

use crate::*;
use async_trait::*;
use std::num::NonZeroUsize;

/// Trait for types that can sign data asynchronously
#[async_trait]
pub trait AsyncSigner: Signer {
    /// Attempt to sign the data asynchronously
    async fn try_sign_async(&self, key: &Self::Key, data: &[u8]) -> Result<Self::Signature, Error>;

    /// Sign the data asynchronously
    async fn sign_async(&self, key: &Self::Key, data: &[u8]) -> Self::Signature {
        self.try_sign_async(key, data)
            .await
            .expect("signing operation failed")
    }
}

/// Trait for types that can verify data asynchronously
#[async_trait]
pub trait AsyncVerifier: Verifier {
    /// Verify the data asynchronously
    async fn verify_async(
        &self,
        key: &Self::Key,
        data: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Error>;
}

/// Trait for types that can encrypt data asynchronously
#[async_trait]
pub trait AsyncEncryptor: Encryptor {
    /// Attempt to encrypt the data asynchronously
    async fn try_encrypt_async(
        &self,
        key: &Self::Key,
        plaintext: &Self::Plaintext,
    ) -> Result<Self::Ciphertext, Error>;

    /// Encrypt the data asynchronously
    async fn encrypt_async(
        &self,
        key: &Self::Key,
        plaintext: &Self::Plaintext,
    ) -> Self::Ciphertext {
        self.try_encrypt_async(key, plaintext)
            .await
            .expect("encryption operation failed")
    }
}

/// Trait for types that can decrypt data asynchronously
#[async_trait]
pub trait AsyncDecryptor: Decryptor {
    /// Decrypt the data asynchronously
    async fn decrypt_async(
        &self,
        key: &Self::Key,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Error>;
}

/// Trait for types that can split a secret into shares asynchronously
#[async_trait]
pub trait AsyncSecretSplitter: SecretSplitter {
    /// Split the secret into shares asynchronously
    async fn split_async(
        &self,
        secret: &Self::Secret,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> Result<Self::Output, Error>;

    /// Split the secret into shares with the given identifiers asynchronously
    async fn split_with_identifiers_async(
        &self,
        secret: &Self::Secret,
        threshold: NonZeroUsize,
        identifiers: &[Self::Identifier],
    ) -> Result<Self::Output, Error>;
}

/// Trait for types that can combine shares into a secret asynchronously
#[async_trait]
pub trait AsyncSecretCombiner: SecretCombiner {
    /// Combine the shares into a secret asynchronously
    async fn combine_async(
        &self,
        shares: &[(Self::Identifier, Self::Shares)],
    ) -> Result<Self::Secret, Error>;
}

/// Trait for types that can get a key asynchronously
#[async_trait]
pub trait AsyncGetKey: GetKey {
    /// Get the key asynchronously
    async fn get_key_async(
        &self,
        key_path: &Self::KeyPath,
        codec: &Self::Codec,
        threshold: usize,
        limit: usize,
    ) -> Result<Self::Key, Error>;
}
