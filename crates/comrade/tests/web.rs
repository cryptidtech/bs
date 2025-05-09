//! Test to ensure that the crate runs in wasm32 target
#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::wasm_bindgen_test_configure;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

// Test which checks autotrait implementation for all types
fn is_normal<T: Sized + Send + Sync + Unpin>() {}

#[wasm_bindgen_test]
async fn test_wasm_autotraits() {
    // This is a dummy test to ensure that the crate runs in wasm32 target
    // and that the autotrait implementation is what is expected.
    struct Current;
    struct Proposed;
    is_normal::<comrade::Comrade<Current, Proposed>>();
}
