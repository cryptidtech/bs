#![cfg(target_arch = "wasm32")]
#![cfg(test)]
use bs_peer::utils;
use wasm_bindgen_test::wasm_bindgen_test_configure;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn basic_test() {
    utils::run_basic_test().await;
}

#[wasm_bindgen_test]
async fn in_memory_blockstore_test() {
    utils::run_in_memory_blockstore_test().await;
}

#[wasm_bindgen_test]
async fn test_store_entries() {
    utils::run_store_entries_test().await;
}

#[wasm_bindgen_test]
async fn run_update_test() {
    utils::run_update_test().await;
}

#[wasm_bindgen_test]
async fn run_load_test() {
    utils::run_load_test().await;
}

#[wasm_bindgen_test]
async fn test_peer_initialization() {
    // init_logger();
    utils::run_peer_initialization_test().await;
}
