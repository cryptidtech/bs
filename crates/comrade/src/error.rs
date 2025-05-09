//! Crate errors

/// Comrade error types
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    // /// Error in the VM
    // #[error("VM error: {0}")]
    // Vm(#[from] wasmi::Error),
    // /// Error in the component
    // #[error("Component error: {0}")]
    // Component(#[from] comrade_reference::Error),
    // /// Error in the script
    // #[error("Script error: {0}")]
    // Script(#[from] comrade_reference::ScriptError),
}
