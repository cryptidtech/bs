//! browser specific bindings
use thiserror::Error;

mod opfs;
pub use opfs::OPFSWrapped;

mod crypto;

#[derive(Error, Debug)]
pub enum Error {
    /// From<Infallible>
    #[error("Infallible")]
    Infallible(#[from] std::convert::Infallible),
    /// From<libp2p::multiaddr::Error>
    #[error("Multiaddr error")]
    Multiaddr(#[from] libp2p::multiaddr::Error),
    /// From<DialError>
    #[error("Dial error")]
    Dial(#[from] libp2p::swarm::DialError),
    /// From core::Error
    #[error("Core error {0}")]
    Core(#[from] bs_p2p::Error),
    /// From futures channel mspc send Error
    #[error("Send error {0}")]
    Send(#[from] futures::channel::mpsc::SendError),

    /// anyhow
    #[error("Anyhow error {0}")]
    Anyhow(#[from] anyhow::Error),

    /// From String
    #[error("{0}")]
    String(String),

    /// From<std::io::Error>
    #[error("IO error {0}")]
    Io(#[from] std::io::Error),

    /// Error creatign OPFS Blockstore
    #[error("OPFS Blockstore Error: {0}")]
    OPFSBlockstore(String),
}
