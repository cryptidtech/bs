#![cfg(target_arch = "wasm32")]
use bs_wallets::memory::*;
use multicodec::Codec;
use multikey::mk;
// use wasm_bindgen::{JsError, JsValue};
use wasm_bindgen_test::wasm_bindgen_test_configure;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn basic_test() {
    // We create a Plog and Vlad and save the data to the Browser Blockstore
    // To crteate a new Peer, we call default() to get default values.
    let seed: [u8; 32] = [42; 32];
    let codec = Codec::Ed25519Priv;
    let _mk = mk::Builder::new_from_seed(codec, &seed)
        .unwrap()
        .try_build()
        .unwrap();

    let key_manager = InMemoryKeyManager::default();
    let _p = bs_peer::peer::BsPeer::new(key_manager).await.unwrap();

    // create
    // update
    // connect
    // events
}
