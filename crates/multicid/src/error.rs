// SPDX-License-Idnetifier: Apache-2.0

/// Errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A multicodec decoding error
    #[error(transparent)]
    Multicodec(#[from] multicodec::Error),
    /// A multihash error
    #[error(transparent)]
    Multihash(#[from] multihash::Error),
    /// A mulikey error
    #[error(transparent)]
    Multikey(#[from] multikey::Error),
    /// A multisig error
    #[error(transparent)]
    Multisig(#[from] multisig::Error),
    /// Cid error
    #[error(transparent)]
    Cid(#[from] CidError),
    /// Vlad error
    #[error(transparent)]
    Vlad(#[from] VladError),
}

/// Cid Errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CidError {
    /// Missing target codec
    #[error("Missing target data encoding codec")]
    MissingTargetCodec,
    /// Missing hash data
    #[error("Missing hash data")]
    MissingHash,
    /// Trying to build a legacy Cid using the wrong function
    #[error("Building legacy Cid with the wrong function")]
    LegacyCid,
    /// Trying to build a modern Cid using the wrong function
    #[error("Building modern Cid with the wrong function")]
    ModernCid,
}

/// Vlad Errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VladError {
    /// Missing sigil 0x07
    #[error("Missing Vlad sigil")]
    MissingSigil,
    /// Missing nonce
    #[error("Missing nonce")]
    MissingNonce,
    /// Missing nonce
    #[error("Missing cid")]
    MissingCid,
}
