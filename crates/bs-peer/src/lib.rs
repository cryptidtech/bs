//! BetterSign Peer

// include readme
#![doc = include_str!("../README.md")]

// Test the README.md code snippets
#[cfg(doctest)]
pub struct ReadmeDoctests;

pub mod peer;
pub use peer::{BsPeer, DefaultBsPeer};

pub mod platform;

pub mod error;
pub use error::Error;

mod config;

// #[cfg(any(test, target_arch = "wasm32"))]
pub mod test_utils;
