//! BetterSign peer to peer communication

/// Entry point for the crate. Create a libp2p swarm either natively or in wasm32.
pub mod swarm;

mod error;
pub use error::Error;
