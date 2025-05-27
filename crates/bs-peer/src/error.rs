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
}
