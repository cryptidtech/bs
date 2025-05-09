//! Test to ensure that the crate runs in wasm32 target
#![cfg(target_arch = "wasm32")]

use std::collections::HashMap;

use comrade_reference::{Pairable, Pairs, Value};
use wasm_bindgen_test::wasm_bindgen_test_configure;
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_browser);

// Test which checks autotrait implementation for all types
fn is_normal<T: Sized + Send + Sync + Unpin>() {}

fn is_not_send<T: Sized + Unpin>() {}

#[wasm_bindgen_test]
async fn test_wasm_autotraits() {
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

    is_not_send::<comrade::Comrade<ContextPairs, ContextPairs>>();
    // is_normal::<comrade::Comrade<ContextPairs, ContextPairs>>();
}
