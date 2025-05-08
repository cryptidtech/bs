//! Comrade Virutal Machine runs the script using the chosen wasm component.
use comrade_reference::Value;

use crate::Error;

/// Run the script.
pub(crate) fn run(script: &str) -> Result<(), Error> {
    todo!();
    Ok(())
}

/// Get the top value from the context return stack.
pub(crate) fn top() -> Option<Value> {
    todo!()
}
