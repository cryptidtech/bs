//! Comrade Virutal runtime which manages running of the script using the chosen wasm component.
use crate::Error;
use comrade_reference::Value;

/// Feature `wasm_component_layer` enables the use of a wasm component layer
// Commented out for now, so we get rust-analyzer to not complain about unused code
// #[cfg(feature = "wasm_component_layer")]
mod layer;
// #[cfg(feature = "wasm_component_layer")]
pub(crate) use layer::Runner;

// Other wasm runtimes can be used:
// mod wasm_time;
// mod wasm_i;
// mod wasmer;

/// Each runtime feature must implement the `Runtime` trait, run and top
pub trait Runtime {
    /// Run the script.
    fn try_unlock(&mut self, script: &str) -> Result<(), Error>;
    /// Get the top value from the context return stack.
    fn try_lock(&mut self, script: &str) -> Result<Option<Value>, Error>;
}
