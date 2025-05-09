//! Crate errors

/// Comrade error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid argument: {0}")]
    WasmFnCall(#[from] anyhow::Error),
    /// Error in the  Script
    #[error("Script has failed to run, yuo likely have an error in your script: {0}")]
    ScriptFailure(String),
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
