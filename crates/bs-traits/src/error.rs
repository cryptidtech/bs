// SPDX-License-Identifier: FSL-1.1

/// Error type for the crates
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Signing operation failed
    #[error("signing operation failed")]
    SignError,

    /// Verification operation failed
    #[error("verification operation failed")]
    VerifyError,

    /// Encryption operation failed
    #[error("encryption operation failed")]
    EncryptError,

    /// Decryption operation failed
    #[error("decryption operation failed")]
    DecryptError,

    /// Key retrieval operation failed
    #[error("key retrieval operation failed")]
    KeyError,
}
