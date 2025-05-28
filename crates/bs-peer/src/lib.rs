//! BetterSign Peer

// include readme
#![doc = include_str!("../README.md")]

// Test the README.md code snippets
#[cfg(doctest)]
pub struct ReadmeDoctests;

pub mod peer;
pub use peer::BsPeer;

mod platform;

pub mod bindgen;

pub mod error;
pub use error::Error;

mod config;
