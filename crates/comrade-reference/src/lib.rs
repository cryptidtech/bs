// Include readme at header, with rustdoc tests
#![doc = include_str!("../README.md")]
pub struct ReadmeDocumentation;

/// Crate level errors
mod error;
pub use error::ApiError;

/// Context is the main entry of this crate
mod context;
/// Public re-exports
pub use context::{Context, Log, Pairs, Stack, Value};
