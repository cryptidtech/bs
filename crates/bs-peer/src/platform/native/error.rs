#[derive(thiserror::Error, Debug)]
pub enum NativeError {
    #[error("Error: {0}")]
    P2p(#[from] bs_p2p::Error),

    /// From<libp2p::multiaddr::Error>
    #[error("Multiaddr error")]
    Multiaddr(#[from] libp2p::multiaddr::Error),

    /// From<libp2p::libp2p_identity::ParseError>
    #[error("Identity error")]
    Identity(#[from] libp2p::identity::ParseError),

    /// No data directory
    #[error("No data directory")]
    NoDataDir,

    /// Input output error
    #[error("IO error")]
    Io(#[from] std::io::Error),

    /// from anyhow
    #[error("error")]
    Anyhow(#[from] anyhow::Error),

    // From<std::string::String>
    #[error("Error: {0}")]
    String(String),
}

impl From<String> for NativeError {
    fn from(s: String) -> Self {
        NativeError::String(s)
    }
}

impl From<&str> for NativeError {
    fn from(s: &str) -> Self {
        NativeError::String(s.to_string())
    }
}
