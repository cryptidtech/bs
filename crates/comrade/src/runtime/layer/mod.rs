//! Uses crate wasm_component_layer to runt he wasm components.
//!
//! This crate is great because it gives us the ability to isomorphically run in the browser with
//! wasm_bindgen but without javascript, and also natively.
use super::Runtime;
use crate::Error;
use comrade_reference::Value;

// wasmi layer for native targets
#[cfg(not(target_arch = "wasm32"))]
use wasmi_runtime_layer as runtime_layer;

// JS layer for the browser
#[cfg(target_arch = "wasm32")]
use js_wasm_runtime_layer as runtime_layer;

// /// Run the script.
// pub(crate) fn run(script: &str) -> Result<(), Error> {
//     todo!();
//     Ok(())
// }
//
// /// Get the top value from the context return stack.
// pub(crate) fn top() -> Option<Value> {
//     todo!()
// }

#[derive(Debug, Default)]
pub(crate) struct Runner;

impl Runtime for Runner {
    fn run(&self, script: &str) -> Result<(), Error> {
        todo!()
    }

    fn top(&self) -> Option<Value> {
        todo!()
    }
}
