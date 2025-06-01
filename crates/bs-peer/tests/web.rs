#![cfg(target_arch = "wasm32")]
#![cfg(test)]
use bs_peer::test_utils;
use wasm_bindgen_test::wasm_bindgen_test_configure;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn basic_test() {
    test_utils::run_basic_test().await;
}

#[wasm_bindgen_test]
async fn in_memory_blockstore_test() {
    test_utils::run_in_memory_blockstore_test().await;
}

#[wasm_bindgen_test]
async fn test_store_entries() {
    test_utils::run_store_entries_test().await;
}
