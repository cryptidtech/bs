use wasm_bindgen::{JsError, JsValue};
use wasm_bindgen_test::wasm_bindgen_test_configure;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn basic_test() {
    // We create a Plog and Vlad and save the data to the Browser Blockstore
    // To crteate a new Peer, we call default() to get default values.
    // let p = bs_peer::peer::BsPeer::new().await.unwrap();
}
