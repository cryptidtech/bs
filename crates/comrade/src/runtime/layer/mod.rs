//! Uses crate wasm_component_layer to runt he wasm components.
//!
//! This crate is great because it gives us the ability to isomorphically run in the browser with
//! wasm_bindgen but without javascript, and also natively.
use super::Runtime;
use crate::Error;
use comrade_reference::Value;
use wasm_component_layer::{Component, Engine, Linker, Store};

// wasmi layer for native targets
#[cfg(not(target_arch = "wasm32"))]
use wasmi_runtime_layer as runtime_layer;

// JS layer for the browser
#[cfg(target_arch = "wasm32")]
use js_wasm_runtime_layer as runtime_layer;

#[derive(Clone, Default, Debug)]
struct Data;

#[derive(Debug)]
pub(crate) struct Runner;

impl Default for Runner {
    /// Create a new runner.
    fn default() -> Self {
        // target/wasm32-unknown-unknown/release/comrade_component.wasm
        let bytes: &[u8] = include_bytes!(
            "../../../../../target/wasm32-unknown-unknown/release/comrade_component.wasm"
        );

        let data = Data::default();

        // Create a new engine for instantiating a component.
        let engine = Engine::new(runtime_layer::Engine::default());

        // Create a store for managing WASM data and any custom user-defined state.
        let mut store = Store::new(&engine, data);

        tracing::debug!("Created store, loading bytes.",);
        // Parse the component bytes and load its imports and exports.
        let component = Component::new(&engine, &bytes).unwrap();

        tracing::debug!("Loaded bytes");

        // Create a linker that will be used to resolve the component's imports, if any.
        let mut linker = Linker::default();

        Self
    }
}

impl Runtime for Runner {
    fn run(&self, script: &str) -> Result<(), Error> {
        Ok(())
    }

    fn top(&self) -> Option<Value> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::Runtime;
    use comrade_reference::Value;

    #[test]
    fn test_runner() {
        let runner = Runner::default();
        assert_eq!(runner.top(), None);
        assert!(runner.run("test").is_ok());
    }
}
