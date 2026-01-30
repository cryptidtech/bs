//! Test to ensure that the crate runs in wasm32 target
#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::wasm_bindgen_test_configure;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

use comrade_reference::{Pairs, Value};
use std::collections::HashMap;
use tracing::info;

use comrade::wasm_tests::run as run_wasm_tests;

// Test which checks autotrait implementation for all types
fn is_not_send<T: Sized + Unpin>() {}

fn init_tracing() {
    // Set up panic hook for better error messages
    console_error_panic_hook::set_once();

    // Initialize the tracing subscriber with console output
    tracing_wasm::set_as_global_default();
}

#[wasm_bindgen_test]
fn test_wasm_autotraits() {
    // This is a dummy test to ensure that the crate runs in wasm32 target
    // and that the autotrait implementation is what is expected.
    #[derive(Clone, Debug, Default)]
    struct ContextPairs(HashMap<String, Value>);

    impl Pairs for ContextPairs {
        fn get(&self, key: &str) -> Option<Value> {
            self.0.get(key).cloned()
        }

        fn put(&mut self, key: &str, value: &Value) -> Option<Value> {
            self.0.insert(key.to_string(), value.clone())
        }
    }

    is_not_send::<comrade::Comrade<'_>>();
}

#[wasm_bindgen_test]
fn web_test() {
    init_tracing();

    tracing::info!("Starting web_test");

    // Import and run the same tests that are in lib.rs
    comrade::wasm_tests::run();
}
