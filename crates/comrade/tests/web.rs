//! Test to ensure that the crate runs in wasm32 target
#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::wasm_bindgen_test_configure;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

use comrade_reference::{Pairable, Pairs, Value};
use std::collections::HashMap;
use tracing::info;

use comrade::wasm_tests::run as run_wasm_tests;

// Test which checks autotrait implementation for all types
fn is_normal<T: Sized + Send + Sync + Unpin>() {}

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

    is_not_send::<comrade::Comrade<ContextPairs, ContextPairs>>();
    // is_normal::<comrade::Comrade<ContextPairs, ContextPairs>>();
}

#[wasm_bindgen_test]
fn test_comrade_wasm32_api() {
    use comrade::Comrade;
    use comrade_reference::Pairs;
    use std::collections::HashMap;

    init_tracing();

    info!("Starting test_example");

    #[derive(Clone, Default, Debug)]
    pub struct TestData(HashMap<String, Value>);

    impl Pairs for TestData {
        fn get(&self, key: &str) -> Option<Value> {
            self.0.get(key).cloned()
        }

        fn put(&mut self, key: &str, value: &Value) -> Option<Value> {
            self.0.insert(key.to_string(), value.clone())
        }
    }

    fn unlock_script(entry_key: &str, proof_key: &str) -> String {
        let unlock_script = format!(
            r#"
                // push the serialized Entry as the message
                push("{entry_key}"); 

                // push the proof data
                push("{proof_key}");
            "#
        );

        unlock_script
    }

    /// First lock is /ephemeral and {entry_key}
    fn first_lock_script(entry_key: &str) -> String {
        let first_lock = format!(
            r#"
                // check the first key, which is ephemeral
                check_signature("/ephemeral", "{entry_key}") 
            "#
        );

        first_lock
    }

    /// Other lock script
    fn other_lock_script(entry_key: &str) -> String {
        format!(
            r#"
                // then check a possible threshold sig...
                check_signature("/recoverykey", "{entry_key}") ||

                // then check a possible pubkey sig...
                check_signature("/pubkey", "{entry_key}") ||
                
                // then the pre-image proof...
                check_preimage("/hash")
            "#
        )
    }

    // cfg test or wasm32
    fn proof_data() -> Vec<u8> {
        hex::decode("b92483a6c006000100404819397f51b18bc6cffd1fff07afa33f7096c7a0c659590b077cc0ea5d6081d739512129becacb8e6997e6b7d18756299f515a822344ac2b6737979d5e5e6b03").unwrap()
    }

    fn pub_key() -> Vec<u8> {
        hex::decode("ba24ed010874657374206b657901012054d94d7b8a11d6581af4a14bc6451c7a23049018610f108c996968fe8fce9464").unwrap()
    }

    // The message to sign, in both the lock and unlock scripts
    let entry_key = "/entry/";
    let entry_data = b"for great justice, move every zig!";

    // The proof data that is provided by the unlock script
    let proof_key = "/entry/proof";
    let proof_data = proof_data();

    // The public key to that must be proven by unlock scripts
    let pubkey = "/pubkey";
    let pub_key = pub_key();

    // Our Key-Value Pairs
    let mut kvp_unlock = TestData::default();
    let mut kvp_lock = TestData::default();

    // "/entry/" needs to be present on both lock and unlock stacks,
    // since they are used in both the unlock and lock scripts:
    // ie. push("/entry/") and check_signature("/pubkey", "/entry/")
    kvp_unlock.put(entry_key, &entry_data.to_vec().into());
    kvp_lock.put(entry_key, &entry_data.to_vec().into());

    // "/entry/proof" only needs to be present on the unlock stack,
    // since that's where the proof is used
    kvp_unlock.put(proof_key, &proof_data.clone().into());

    // "/pubkey" needs to be present on lock stack, to set what the PubKey is
    kvp_lock.put(pubkey, &pub_key.into());

    let unlock_script = format!(
        r#"
        // push the serialized Entry as the message
        push("{entry_key}"); 

        // push the proof data
        push("{proof_key}");
    "#
    );

    let first_lock = format!(
        r#"
        // check the first key, which is ephemeral
        check_signature("/ephemeral", "{entry_key}") 
    "#
    );

    let other_lock_script = format!(
        r#"
        // then check a possible threshold sig...
        check_signature("/recoverykey", "{entry_key}") ||

        // then check a possible pubkey sig...
        check_signature("/pubkey", "{entry_key}") ||
        
        // then the pre-image proof...
        check_preimage("/hash")
    "#
    );

    let mut comrade = Comrade::new(kvp_lock, kvp_unlock)
        .try_unlock(&unlock_script)
        .expect("Failed to unlock comrade");

    // check the lock scripts
    let locks = [first_lock, other_lock_script];

    // check the locks
    let mut count = 0;
    for lock in locks {
        if let Some(Value::Success(ct)) = comrade.try_lock(&lock).expect("Failed to lock comrade") {
            count = ct;
            break;
        }
    }

    // check the count
    assert_eq!(count, 2);
}
