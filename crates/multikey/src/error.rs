// SPDX-License-Idnetifier: Apache-2.0
/// Errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Attributes error
    #[error(transparent)]
    Attributes(#[from] AttributesError),
    /// Conversions error
    #[error(transparent)]
    Conversions(#[from] ConversionsError),
    /// Cipher error
    #[error(transparent)]
    Cipher(#[from] CipherError),
    /// Kdf error
    #[error(transparent)]
    Kdf(#[from] KdfError),
    /// Nonce error
    #[error(transparent)]
    Nonce(#[from] NonceError),
    /// Sign error
    #[error(transparent)]
    Sign(#[from] SignError),
    /// Threshold error
    #[error(transparent)]
    Threshold(#[from] ThresholdError),
    /// Verify error
    #[error(transparent)]
    Verify(#[from] VerifyError),

    /// Multibase conversion error
    #[error(transparent)]
    Multibase(#[from] multibase::Error),
    /// Multicodec decoding error
    #[error(transparent)]
    Multicodec(#[from] multicodec::Error),
    /// Multiutil error
    #[error(transparent)]
    Multiutil(#[from] multiutil::Error),
    /// Multisig error
    #[error(transparent)]
    Multisig(#[from] multisig::Error),
    /// Multitrait error
    #[error(transparent)]
    Multitrait(#[from] multitrait::Error),
    /// Multihash error
    #[error(transparent)]
    Multihash(#[from] multihash::Error),

    /// Utf8 error
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
    /// Duplicate attribute error
    #[error("Duplicate Multikey attribute: {0}")]
    DuplicateAttribute(u8),
    /// Incorrect Multikey sigil
    #[error("Missing Multikey sigil")]
    MissingSigil,
    /// Unsupported key algorithm
    #[error("Unsupported key algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// Attributes errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttributesError {
    /// Error with the key codec
    #[error("Unsupported key codec: {0}")]
    UnsupportedCodec(multicodec::Codec),
    /// No key data attribute
    #[error("Key data unit missing")]
    MissingKey,
    /// Not a secret key
    #[error("Not a secret key {0}")]
    NotSecretKey(multicodec::codec::Codec),
    /// Key is encrypted
    #[error("Key is encrypted")]
    EncryptedKey,
    /// Invalid attribute name
    #[error("Invalid attribute name {0}")]
    InvalidAttributeName(String),
    /// Invalid attribute value
    #[error("Invalid attribute value {0}")]
    InvalidAttributeValue(u8),
    /// No threshold
    #[error("Missing threshold")]
    MissingThreshold,
    /// No limit
    #[error("Missing limit")]
    MissingLimit,
    /// No key share identifier
    #[error("Missing share identifier")]
    MissingShareIdentifier,
    /// No threshold data
    #[error("Missing threshold data")]
    MissingThresholdData,
}

/// Conversions errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConversionsError {
    /// Ssh key error
    #[error(transparent)]
    Ssh(#[from] SshErrors),
    /// Public key operation failure
    #[error("Public key error: {0}")]
    PublicKeyFailure(String),
    /// Secret key operation failure
    #[error("Secret key error: {0}")]
    SecretKeyFailure(String),
    /// Error converting from ssh keys
    #[error("Unsupported SSH key algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// Error with the key codec
    #[error("Unsupported key codec: {0}")]
    UnsupportedCodec(multicodec::Codec),
}

/// SSH Encoding Errors that cannot be handled by thiserror since they may not use the std feature
/// in the case of wasm32 target.
#[derive(Clone, Debug)]
pub enum SshErrors {
    /// Error from [ssh_key::Error]
    Key(ssh_key::Error),
    /// Invalid label from [ssh_encoding::LabelError]
    KeyLabel(ssh_encoding::LabelError),
    /// Unexpected trailing data at end of message from [ssh_encoding::Error]
    Encoding(ssh_encoding::Error),
}

/// Impl Display for EncodingError
impl std::fmt::Display for SshErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshErrors::Key(err) => write!(f, "{}", err),
            SshErrors::KeyLabel(err) => write!(f, "{}", err),
            SshErrors::Encoding(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for SshErrors {}

impl From<ssh_encoding::Error> for SshErrors {
    fn from(err: ssh_encoding::Error) -> Self {
        SshErrors::Encoding(err)
    }
}

impl From<ssh_key::Error> for SshErrors {
    fn from(err: ssh_key::Error) -> Self {
        SshErrors::Key(err)
    }
}

impl From<ssh_encoding::LabelError> for SshErrors {
    fn from(err: ssh_encoding::LabelError) -> Self {
        SshErrors::KeyLabel(err)
    }
}

/// Cipher errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CipherError {
    /// Error with the cipher codec
    #[error("Unsupported cipher codec: {0}")]
    UnsupportedCodec(multicodec::Codec),
    /// Missing codec
    #[error("Missing cipher codec")]
    MissingCodec,
    /// Missing nonce error
    #[error("Missing cipher nonce")]
    MissingNonce,
    /// Missing nonce length error
    #[error("Invalid cipher nonce length")]
    InvalidNonceLen,
    /// Invalid nonce error
    #[error("Invalid cipher nonce")]
    InvalidNonce,
    /// Missing key error
    #[error("Missing cipher key")]
    MissingKey,
    /// Missing key length error
    #[error("Missing cipher key length")]
    MissingKeyLen,
    /// Invalid key error
    #[error("Invalid cipher key")]
    InvalidKey,
    /// Encryption error
    #[error("Encryption error: {0}")]
    EncryptionFailed(String),
    /// Decryption error
    #[error("Decryption failed")]
    DecryptionFailed,
}

/// Kdf errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KdfError {
    /// Bcrypt PBKDF error
    #[error(transparent)]
    Bcrypt(#[from] bcrypt_pbkdf::Error),
    /// Error with the KDF codec
    #[error("Unsupported KDF codec: {0}")]
    UnsupportedCodec(multicodec::Codec),
    /// Missing codec
    #[error("Missing KDF codec")]
    MissingCodec,
    /// Missing salt error
    #[error("Missing KDF salt")]
    MissingSalt,
    /// Invalid salt length error
    #[error("Invalid KDF salt length")]
    InvalidSaltLen,
    /// Missing rounds error
    #[error("Missing KDF rounds")]
    MissingRounds,
}

/// Nonce errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NonceError {
    /// Missing sigil
    #[error("Missing Nonce codec")]
    MissingSigil,
    /// Missing bytes
    #[error("Missing Nonce bytes")]
    MissingBytes,
}

/// Sign errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// Not a signing key
    #[error("Not a signing key")]
    NotSigningKey,
    /// Signing failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    /// Missing scheme
    #[error("Missing signature scheme")]
    MissingScheme,
}

/// Threshold errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ThresholdError {
    /// Bls error
    #[error(transparent)]
    Bls(#[from] blsful::BlsError),
    /// Invalid threshold and limit
    #[error("Invalid threshold ({0}) and limit ({1}). Limit must be greater than threshold")]
    InvalidThresholdLimit(usize, usize),
    /// Not a secret key
    #[error("Not a secret key; only secret keys may be split and combined")]
    NotASecretKey,
    /// Is a key share when we expect a key
    #[error("Is a key share when we expect a key")]
    IsAKeyShare,
    /// Not enough shares
    #[error("Not enough shares to combine")]
    NotEnoughShares,
    /// Share combine failed
    #[error("Combining secret key shares failed: {0}")]
    ShareCombineFailed(String),
}

/// Verify errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// Missing signature
    #[error("Missing signature")]
    MissingSignature,
    /// Missing message
    #[error("Missing message")]
    MissingMessage,
    /// Bad signature
    #[error("Bad signature: {0}")]
    BadSignature(String),
}
