//! Comrade Virutal runtime which manages running of the script using the chosen wasm component.
use crate::Error;
use comrade_reference::Value;

/// Feature `wasm_component_layer` enables the use of a wasm component layer
// #[cfg(feature = "wasm_component_layer")]
mod layer;
// #[cfg(feature = "wasm_component_layer")]
pub(crate) use layer::{run, top};

/// Each runtime feature must implement the `Runtime` trait, run and top
pub trait Runtime {
    /// Run the script.
    fn run(script: &str) -> Result<(), Error>;
    /// Get the top value from the context return stack.
    fn top() -> Option<Value>;
}
