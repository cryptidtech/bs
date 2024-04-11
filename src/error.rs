// SPDX-License-Identifier: FSL-1.1
/// Errors generated from this crate
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// SshAgent Error
    #[error(transparent)]
    Ssh(#[from] SshError),
    /// Formatting error
    #[error(transparent)]
    Fmt(#[from] std::fmt::Error),
    /// I/O error
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A log crate error
    #[error(transparent)]
    Log(#[from] log::SetLoggerError),
    /// Wasm command error
    #[error(transparent)]
    Wasm(#[from] crate::commands::wasm::Error),
    /// Keygen command error
    #[error(transparent)]
    Keygen(#[from] crate::commands::keygen::Error),


    /// BestPractices error
    #[error(transparent)]
    BestPractices(#[from] best_practices::error::Error),
    /// Multicodec error
    #[error(transparent)]
    Multicodec(#[from] multicodec::Error),
    /// Multihash error
    #[error(transparent)]
    Multihash(#[from] multihash::Error),
    /// Multikey error
    #[error(transparent)]
    Multikey(#[from] multikey::Error),
    /// Multisig error
    #[error(transparent)]
    Multisig(#[from] multisig::Error),
    /// Multiutil error
    #[error(transparent)]
    Multiutil(#[from] multiutil::Error),

    /// Serde CBOR error
    #[error(transparent)]
    SerdeCbor(#[from] serde_cbor::Error),
    /// Toml deserialization error
    #[error(transparent)]
    TomlDe(#[from] toml::de::Error),
    /// Toml serialization error
    #[error(transparent)]
    TomlSer(#[from] toml::ser::Error),
    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Serde JSON error
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),

    /// No valid application config path found
    #[error("No valid config path found")]
    NoHome,
    /// Cannot initialize config file
    #[error("Cannot initialize config file: {0}")]
    CannotInitializeConfig(String),
    /// Invalid environment variable key
    #[error("Invalid environment variable key: {0}")]
    InvalidEnv(String),
    /// No key by that name
    #[error("No key known by: {0}")]
    NoKey(String),
    /// No keychain
    #[error("No keychain available")]
    NoKeychain,
    /// Invalid key type
    #[error("Invalid key type {0}")]
    InvalidKeyType(String),
    /// Invalid backend type
    #[error("Invalid backend type {0}")]
    InvalidBackendType(String),
}

/// SshAgent error
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SshError {
    /// Ssh key error
    #[error(transparent)]
    SshKey(#[from] ssh_key::Error),
    /// Ssh Agent error
    #[error("ssh agent error: {0}")]
    SshAgent(String),
    /// No ssh_agent path
    #[error("No ssh agent path")]
    SshAgentPath,
    /// Not allowed to add keys
    #[error("Adding keys to ssh-agent not allowed")]
    AddingKeysNotAllowed,
    /// Not a public key
    #[error("Not a public key")]
    NotPublicKey,
}
