//! Crate errors

/// Errors that can occur in the BS Wallet  library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// From<multikey::Error>
    #[error("Multikey error: {0}")]
    Multikey(#[from] multikey::Error),
}
