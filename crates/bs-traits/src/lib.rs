// SPDX-License-Identifier: FSL-1.1

/// `bs-traits` is a crate that provides traits for asynchronous and synchronous operations.
///
/// It also provides a `WaitQueue` type that can be used to implement synchronous and asynchronous operations
/// without having to use tokio::block_in_place or similar.
mod r#async;
mod cond_send;
pub use cond_send::{CondSend, CondSync};
mod error;
mod sync;
mod wait_queue;

pub use error::Error;
pub use r#async::*;
pub use sync::*;
pub use wait_queue::*;

use std::fmt::Debug;

/// Trait for types that can sign data using [AsyncSigner] or [SyncSigner]
pub trait Signer {
    /// The type of key used to sign
    type Key;
    /// The type of signature
    type Signature;
    /// Any Signing Error
    type Error: Debug;
}

/// Trait for types that can verify signatures using [AsyncVerifier] or [SyncVerifier]
pub trait Verifier {
    /// The type of key used to verify
    type Key;
    /// The type of signature
    type Signature;
    /// Error type for verification operations
    type Error;
}

/// Trait for types that can encrypt data using [AsyncEncryptor] or [SyncEncryptor]
pub trait Encryptor {
    /// The type of key used to encrypt
    type Key: Send + Sync;
    /// The type of ciphertext
    type Ciphertext: Send + Sync;
    /// The type of plaintext, might include the nonce, and additional authenticated data
    type Plaintext: Send + Sync;
    /// Error type for encryption operations
    type Error: Debug;
}

/// Trait for types that can decrypt data using [AsyncDecryptor] or [SyncDecryptor]
pub trait Decryptor {
    /// The type of key used to decrypt
    type Key: Send + Sync;
    /// The type of ciphertext
    type Ciphertext: Send + Sync;
    /// The type of plaintext
    type Plaintext: Send + Sync;
    /// Error type for decryption operations
    type Error;
}

/// Trait for types that can split a secret into shares, using [AsyncSecretSplitter] or [SyncSecretSplitter]
pub trait SecretSplitter {
    /// The type of secret to split
    type Secret: Send + Sync;
    /// The type of identifier for the shares
    type Identifier: Send + Sync;
    /// The output from splitting the secret.
    /// Might include the threshold and limit used to split the secret,
    /// the shares, and the verifiers, identifiers,
    /// or any other information needed to reconstruct the secret
    /// and verify the shares.
    type Output: Send + Sync;
    /// Error type for secret splitting operations
    type Error;
}

/// Trait for types that can combine shares into a secret, using [AsyncSecretCombiner] or [SyncSecretCombiner]
pub trait SecretCombiner {
    /// The type of secret to combine
    type Secret: Send + Sync;
    /// The type of identifier for the shares
    type Identifier: Send + Sync;
    /// The type of shares to combine
    type Shares: Send + Sync;
    /// Error type for secret combining operations
    type Error;
}

/// Trait for types that can retrieve a key, using [AsyncGetKey] or [SyncGetKey]
pub trait GetKey {
    /// The type of key
    type Key;
    /// The type of key path
    type KeyPath;
    /// The type of codec
    type Codec;
    /// The Error returned
    type Error;
}
