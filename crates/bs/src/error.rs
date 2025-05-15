// SPDX-License-Identifier: FSL-1.1
/// Errors generated from this crate
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Open operation errors
    #[error(transparent)]
    Open(#[from] OpenError),
    /// Update operation errors
    #[error(transparent)]
    Update(#[from] UpdateError),

    /// Traits error
    #[error(transparent)]
    Traits(#[from] bs_traits::Error),

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
    /// Provenance Log error
    #[error(transparent)]
    ProvenanceLog(#[from] provenance_log::Error),

    /// I/O error
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Open op errors
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OpenError {
    /// Invalid CID params
    #[error("Invalid cid params")]
    InvalidCidParams,
    /// Invalid VLAD key params
    #[error("Invalid key params")]
    InvalidKeyParams,
    /// Invalid OpParams
    #[error("Invalid op params")]
    InvalidOpParams,
    /// Invalid VLAD params
    #[error("Invalid vlad params")]
    InvalidVladParams,
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
    /// Invalid CID params
    #[error("Invalid cid params")]
    InvalidCidParams,
    /// Invalid entry
    #[error("Invalid entry")]
    InvalidEntry,
    /// Invalid VLAD key params
    #[error("Invalid key params")]
    InvalidKeyParams,
    /// Invalid OpParams
    #[error("Invalid op params")]
    InvalidOpParams,
    /// No op key-path
    #[error("Missing op key-path")]
    NoOpKeyPath,
    /// No update op value
    #[error("Missing update op value")]
    NoUpdateOpValue,
    /// No last entry
    #[error("No last entry")]
    NoLastEntry,
    /// No entry unlock script given
    #[error("No unlock script for first entry given")]
    NoEntryUnlockScript,
    /// No signing key
    #[error("No entry signing key")]
    NoSigningKey,
}
