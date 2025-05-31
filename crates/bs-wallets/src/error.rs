//! Crate errors

use provenance_log::Key;

/// Errors that can occur in the BS Wallet  library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// From<multikey::Error>
    #[error("Multikey error: {0}")]
    Multikey(#[from] multikey::Error),

    /// No key present for that KeyPath
    #[error("No key present for that KeyPath {0}")]
    NoKeyPresent(Key),

    /// From<multihash::Error>
    #[error("Multihash error: {0}")]
    Multihash(#[from] multihash::Error),

    /// From<multicid::Error>
    #[error("Multicid error: {0}")]
    Multicid(#[from] multicid::Error),
}
