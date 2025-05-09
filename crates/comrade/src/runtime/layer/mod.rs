//! Comrade Virutal runtime which manages running of the script using the chosen wasm component.
use crate::Error;
use comrade_reference::Value;

#[cfg(not(target_arch = "wasm32"))]
use wasmi_runtime_layer as runtime_layer;

#[cfg(target_arch = "wasm32")]
use js_wasm_runtime_layer as runtime_layer;

/// Run the script.
pub(crate) fn run(script: &str) -> Result<(), Error> {
    todo!();
    Ok(())
}

/// Get the top value from the context return stack.
pub(crate) fn top() -> Option<Value> {
    todo!()
}
