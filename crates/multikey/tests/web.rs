#![cfg(target_arch = "wasm32")]

use multicodec::Codec;
use multikey::{Builder, Views};
use wasm_bindgen_test::*;

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_p256_wasm_compatibility() {
    let mut rng = rand_core_6::OsRng;

    let secret_key = Builder::new_from_random_bytes(Codec::P256Priv, &mut rng)
        .unwrap()
        .try_build()
        .unwrap();

    let public_key = secret_key.conv_view().unwrap().to_public_key().unwrap();

    let message = b"wasm test";
    let signature = secret_key
        .sign_view()
        .unwrap()
        .sign(message, false, None)
        .unwrap();

    let result = public_key
        .verify_view()
        .unwrap()
        .verify(&signature, Some(message));

    assert!(result.is_ok());
}
