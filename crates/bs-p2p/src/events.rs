//! Event types, and loop handlers for the P2P network.
pub mod api;

pub mod delay;
use api::Libp2pEvent;
pub(crate) use delay::Delay;

use libp2p::Multiaddr;

#[derive(Debug, Clone)]
pub enum PublicEvent {
    ListenAddr {
        address: Multiaddr,
    },
    Error {
        error: NetworkError,
    },
    Pong {
        peer: String,
        rtt: u64,
    },
    /// Data received from a peer about a topic.
    Message {
        peer: String,
        topic: String,
        data: Vec<u8>,
    },
    /// A Request was made to us, that we may or may not respond to based on screening criteria.
    Request {
        request: Vec<u8>,
        peer: String,
    },
    NewConnection {
        peer: String,
    },
    ConnectionClosed {
        peer: String,
        cause: String,
    },
    Connected,
    Swarm(Libp2pEvent),
}

#[derive(Debug, Clone)]
pub enum NetworkError {
    DialFailed,
    ListenFailed,
    PublishFailed,
    SubscribeFailed,
    UnsubscribeFailed,
}
