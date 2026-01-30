//! BsPeer Errors
use thiserror::Error;

/// Errors that can occur in the BsPeer library.
#[derive(Error, Debug)]
pub enum Error {
    /// Error from the P2P library.
    #[error("P2P error: {0}")]
    P2p(#[from] bs_p2p::Error),

    /// Error from the multiaddr library.
    #[error("Multiaddr error: {0}")]
    Multiaddr(#[from] libp2p::multiaddr::Error),

    /// Error from the identity library.
    #[error("Identity error: {0}")]
    Identity(#[from] libp2p::identity::ParseError),

    /// No data directory specified.
    #[error("No data directory specified")]
    NoDataDir,

    /// Input/output error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Platform-specific errors
    #[error("Platform error: {0}")]
    Platform(#[from] crate::platform::Error),

    /// Plog already exists
    #[error("Plog already exists")]
    PlogAlreadyExists,

    /// From<bs::error::OpenError>
    #[error("Open error: {0}")]
    Open(#[from] bs::error::OpenError),

    /// From<bs::error::UpdateError>
    #[error("Update error: {0}")]
    Update(#[from] bs::error::UpdateError),

    /// From<bs::error::Error>
    #[error("Bs error: {0}")]
    Bs(#[from] bs::Error),

    /// From<provenance_log::Error>
    #[error("Provenance log error: {0}")]
    Plog(#[from] provenance_log::Error),

    /// From<multikey::Error>
    #[error("Multikey error: {0}")]
    Multikey(#[from] multikey::Error),

    /// From<multicid::Error>
    #[error("Multicid error: {0}")]
    Multicid(#[from] multicid::Error),

    /// cid::Cid error
    #[error("CID error: {0}")]
    Cid(#[from] cid::Error),

    /// From<multihash::Error>
    #[error("Multihash error: {0}")]
    Multihash(#[from] multihash::Error),

    /// Error during verification of the provenance log.
    #[error("Plog verification failed: {0}")]
    PlogVerificationFailed(provenance_log::Error),

    /// Blockstore error
    #[error("Blockstore error: {0}")]
    Blockstore(#[from] blockstore::Error),

    /// Generic string error
    #[error("{0}")]
    StringError(String),

    /// Plog not initialized
    #[error("Plog not initialized")]
    PlogNotInitialized,

    /// Wallets error
    #[error(transparent)]
    Wallets(#[from] bs_wallets::Error),

    /// No network connection for this peer
    #[error("Peer is not connected to a network")]
    NotConnected,

    /// Mutex Lock Poisoned
    #[error("Mutex lock poisoned")]
    LockPosioned,
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::StringError(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::StringError(s.to_string())
    }
}
