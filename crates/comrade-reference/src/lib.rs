/// Crate level errors
mod error;
pub use error::ApiError;

/// Context is the main entry of this crate
mod context;
/// Public re-exports
pub use context::{Context, Log, Pairable, Pairs, Stack, Value};
