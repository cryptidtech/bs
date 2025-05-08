//! Use the wasmi runtime layer

#[test]
fn test_api_layer_instance() {
    //log with timstamp
    eprintln!("[TestLog] test_instantiate_instance");

    let wasm_path = "target/wasm32-unknown-unknown/release/comrade_component.wasm";
    eprintln!("[TestLog] Looking for wasm file: {wasm_path}");

    // API should be something like:
    //
    // let unlocked = Comrade::new(&unlock, Current(kvp_lock), Proposed(kvp_unlock))
    //     .with_domain("/")
    //     .try_unlock()?;
    //
    // let mut count = 0;
    //
    // for lock in locks {
    //     if let Some(Value::Success(ct)) = unlocked.try_lock(lock)? {
    //         count = ct;
    //         break;
    //     }
    // }
    assert!(true, "Test not implemented");
}
