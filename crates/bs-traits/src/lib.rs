// SPDX-License-Identifier: FSL-1.1

mod error;
pub use error::Error;

use core::num::NonZeroUsize;

/// Trait for types that can sign data
pub trait Signer {
    /// The type of key used to sign
    type Key;
    /// The type of signature
    type Signature;

    /// Attempt to sign the data
    fn try_sign(&self, key: &Self::Key, data: &[u8]) -> Result<Self::Signature, Error>;

    /// Sign the data and return the signature
    fn sign(&self, key: &Self::Key, data: &[u8]) -> Self::Signature {
        self.try_sign(key, data).expect("signing operation failed")
    }
}

/// Trait for types that can verify signatures
pub trait Verifier {
    /// The type of key used to verify
    type Key;
    /// The type of signature
    type Signature;

    /// Verify that the provided signature for the given data is authentic
    fn verify(
        &self,
        key: &Self::Key,
        data: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Error>;
}

/// Trait for types that can encrypt data
pub trait Encryptor {
    /// The type of key used to encrypt
    type Key;
    /// The type of ciphertext
    type Ciphertext;
    /// The type of plaintext, might include the nonce, and additional authenticated data
    type Plaintext;

    /// Attempt to encrypt the plaintext
    fn try_encrypt(
        &self,
        key: &Self::Key,
        plaintext: &Self::Plaintext,
    ) -> Result<Self::Ciphertext, Error>;

    /// Encrypt the plaintext
    fn encrypt(&self, key: &Self::Key, plaintext: &Self::Plaintext) -> Self::Ciphertext {
        self.try_encrypt(key, plaintext)
            .expect("encryption operation failed")
    }
}

/// Trait for types that can decrypt data
pub trait Decryptor {
    /// The type of key used to decrypt
    type Key;
    /// The type of ciphertext
    type Ciphertext;
    /// The type of plaintext
    type Plaintext;

    /// Attempt to decrypt the ciphertext
    fn decrypt(
        &self,
        key: &Self::Key,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Error>;
}

/// Trait for types that can split a secret into shares
pub trait SecretSplitter {
    /// The type of secret to split
    type Secret;
    /// The type of identifier for the shares
    type Identifier;
    /// The output from splitting the secret.
    /// Might include the threshold and limit used to split the secret,
    /// the shares, and the verifiers, identifiers,
    /// or any other information needed to reconstruct the secret
    /// and verify the shares.
    type Output;

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
    ) -> Result<Self::Output, Error>;

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
    ) -> Result<Self::Output, Error>;
}

/// Trait for types that can combine shares into a secret
pub trait SecretCombiner {
    /// The type of secret to combine
    type Secret;
    /// The type of identifier for the shares
    type Identifier;
    /// The type of shares to combine
    type Shares;

    /// Combine the shares into a secret
    fn combine(&self, shares: &[(Self::Identifier, Self::Shares)]) -> Result<Self::Secret, Error>;
}

/// Trait for types that can retrieve a key
pub trait GetKey {
    /// The type of key
    type Key;
    /// The type of key path
    type KeyPath;
    /// The type of codec
    type Codec;

    /// Get the key
    fn get_key(
        &self,
        key_path: &Self::KeyPath,
        codec: &Self::Codec,
        threshold: usize,
        limit: usize,
    ) -> Result<Self::Key, Error>;
}
