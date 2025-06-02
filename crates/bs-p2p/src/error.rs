//! Bs Errors

use crate::events::api::NetworkCommand;
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Error creating the Swarm
    #[error("Error creating the Swarm: {0}")]
    CreateSwarm(String),

    /// From oneshot canceled error  
    #[error("Oneshot canceled")]
    OneshotCanceled(#[from] futures::channel::oneshot::Canceled),

    /// from string
    #[error("Error: {0}")]
    String(String),

    #[error("Multiaddr error")]
    Multiaddr(#[from] libp2p::multiaddr::Error),
    /// From<DialError>
    #[error("Dial error")]
    Dial(#[from] libp2p::swarm::DialError),

    #[error("Libp2p error")]
    GossipSubMessageAuthenticity,

    /// From OutboundFailure
    #[error("OutboundFailure: {0}")]
    OutboundFailure(#[from] libp2p::request_response::OutboundFailure),

    /// SendError
    #[error("Send error")]
    SendError(#[from] futures::channel::mpsc::SendError),

    #[error("Tokio mpsc Send error")]
    TokioSendError(#[from] tokio::sync::mpsc::error::SendError<NetworkCommand>),

    /// From TorySendError
    #[error("Could not send the message")]
    TrySend(#[from] futures::channel::mpsc::TrySendError<NetworkCommand>),

    #[error("Could not send the message")]
    TrySendPublicEvent(#[from] futures::channel::mpsc::TrySendError<crate::events::PublicEvent>),

    /// Send failure
    #[error("Send failure")]
    SendFailure(String),

    /// from &'static str
    #[error("{0}")]
    StaticStr(&'static str),

    /// From TransportError
    #[error("TransportError: {0}")]
    TransportIo(#[from] libp2p::core::transport::TransportError<std::io::Error>),
}
