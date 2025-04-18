// SPDX-License-Identifier: FSL-1.1
/// Errors generated from this crate
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Plog errors
    #[error(transparent)]
    Plog(#[from] PlogError),
    /// SshAgent errors
    #[error(transparent)]
    Ssh(#[from] SshError),

    /// Formatting error
    #[error(transparent)]
    Fmt(#[from] std::fmt::Error),
    /// I/O error
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// An infallible error
    #[error(transparent)]
    Inf(#[from] std::convert::Infallible),
    /// A log error
    #[error(transparent)]
    Log(#[from] Box<dyn std::error::Error + Send + Sync>),

    /// BestPractices error
    #[error(transparent)]
    BestPractices(#[from] best_practices::error::Error),
    /// Bs errors
    #[error(transparent)]
    Bs(#[from] bs::Error),
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

    /// Rustyline error
    #[error(transparent)]
    RustylineReadLineError(#[from] rustyline::error::ReadlineError),

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
    /// Invalid hash type
    #[error("Invalid hash type {0}-{1}")]
    InvalidHashType(String, String),
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

/// Plog errors
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PlogError {
    /// An incorrect key-path
    #[error("Invalid key-path")]
    InvalidKeyPath,
    /// Invalid file params
    #[error("Invalid file params")]
    InvalidFileParams,
    /// Invalid key params
    #[error("Invalid key params")]
    InvalidKeyParams,
    /// An incorrect value type was encountered
    #[error("Invalid WACC value type")]
    InvalidWaccValue,
    /// No p.log command
    #[error("No p.log command")]
    NoCommand,
    /// No first entry
    #[error("P.log missing first entry")]
    NoFirstEntry,
    /// No vlad key in the first entry
    #[error("P.log missing VLAD verification key in first entry")]
    NoVladKey,
    /// No input file given
    #[error("No input file given")]
    NoInputFile,
    /// No key-path specified
    #[error("No key-path specified")]
    NoKeyPath,
    /// No codec specified
    #[error("No codec specified")]
    NoCodec,
    /// No string value given
    #[error("No string value given")]
    NoStringValue,
}
