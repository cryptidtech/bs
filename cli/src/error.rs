// SPDX-License-Identifier: FSL-1.1
/// Errors generated from this crate
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Open operation errors
    #[error(transparent)]
    Open(#[from] OpenError),
    /// SshAgent Error
    #[error(transparent)]
    Ssh(#[from] SshError),
    /// Update operation errors
    #[error(transparent)]
    Update(#[from] UpdateError),

    /// Formatting error
    #[error(transparent)]
    Fmt(#[from] std::fmt::Error),
    /// I/O error
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A log crate error
    #[error(transparent)]
    Log(#[from] log::SetLoggerError),

    /// BestPractices error
    #[error(transparent)]
    BestPractices(#[from] best_practices::error::Error),
    /// Multicid error
    #[error(transparent)]
    Multicid(#[from] multicid::Error),
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
    /// Provenance Log error
    #[error(transparent)]
    ProvenanceLog(#[from] provenance_log::Error),

    /// Serde CBOR error
    #[error(transparent)]
    SerdeCbor(#[from] serde_cbor::Error),
    /// Serde JSON error
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    /// Toml deserialization error
    #[error(transparent)]
    TomlDe(#[from] toml::de::Error),
    /// Toml serialization error
    #[error(transparent)]
    TomlSer(#[from] toml::ser::Error),
    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// No valid application config path found
    #[error("No valid config path found")]
    NoHome,
    /// Cannot initialize config file
    #[error("Cannot initialize config file: {0}")]
    CannotInitializeConfig(String),
    /// Cannot initialize data dir
    #[error("Cannot initialize data dir: {0}")]
    CannotInitializeData(String),
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

/// Open op errors
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OpenError {
    /// No first lock script given
    #[error("No first lock script given")]
    NoFirstLockScript,
    /// No entry lock script given
    #[error("No lock script for first entry given")]
    NoEntryLockScript,
    /// No entry unlock script given
    #[error("No unlock script for first entry given")]
    NoEntryUnlockScript,
}

/// Update op errors
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UpdateError {
    /// No op key-path
    #[error("Missing op key-path")]
    NoOpKeyPath,
    /// No update op value
    #[error("Missing update op value")]
    NoUpdateOpValue,
}
