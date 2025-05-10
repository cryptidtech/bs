//! Comrade is an execution engine for provenance log scripts.
//!
//! It requires a wasm-component plugin to run. A reference implementation is
//! provided in the `comrade-component` crate which uses [comrade_reference]
//!
//! API should be something like:
//!
//! ```ignore
//! let unlocked = Comrade::new(kvp_lock, kvp_unlock)
//!     .with_domain("/")
//!     .try_unlock(&unlock)?;
//!
//! let mut count = 0;
//!
//! for lock in locks {
//!     if let Some(Value::Success(ct)) = unlocked.try_lock(lock)? {
//!         count = ct;
//!         break;
//!     }
//! }
//! ````
//!
//! where the args iml [comrade_reference::Pairs]

// Include readme at header, with rustdoc tests
#![doc = include_str!("../README.md")]
pub struct ReadmeDocumentation;

mod error;
pub use crate::error::Error;

/// The runtime environment for the scripts
mod runtime;

/// Polyfills required to ensure getrandom v0.3 works in wasm32 targets
#[cfg(target_arch = "wasm32")]
mod random;

// Using the same trait out of convenience, the Pairs trait is very basic
use comrade_reference::{Pairable, Value};
use runtime::Runtime as _;

/// Comrade goes starts at [Initial] Stage, then goes to [Unlocked] Stage.
#[derive(Debug)]
pub struct Initial;

/// Comrade goes starts at [Initial] Stage, then goes to [Unlocked] Stage.
#[derive(Debug)]
pub struct Unlocked;

/// Opinionated entry API for using Comrade.
/// Uses the comrade-component reference implementation by default,
/// and wasm_component_layer for runtime. Either can be substituted
/// with prefered alternatives as desired.
pub struct Comrade<'a, Stage = Initial> {
    // /// The key-value pairs asociated with the lock
    // kvp_lock: C,
    // /// The key-value pairs asociated with the unlock
    // kvp_unlock: P,
    runner: runtime::Runner<'a>,
    _stage: std::marker::PhantomData<Stage>,
}

impl<'a> Comrade<'a> {
    /// Creates a new Comrade instance with the given lock and unlock pairs.
    pub fn new(kvp_lock: &'a impl Pairable, kvp_unlock: &'a impl Pairable) -> Self {
        Comrade {
            runner: runtime::Runner::new(kvp_lock, kvp_unlock),
            _stage: std::marker::PhantomData,
        }
    }

    /// Tries to unlock the comrade with the given script.
    /// Will return an error if the script fails to run.
    pub fn try_unlock(mut self, script: &'a str) -> Result<Comrade<'a, Unlocked>, Error> {
        self.runner.try_unlock(script)?;
        Ok(self.into())
    }
}

// try_lock can only be called on an Unlocked Comrade
impl Comrade<'_, Unlocked> {
    /// Tries to lock the comrade with the given script.
    /// Will return an error if the script fails to run.
    pub fn try_lock(&mut self, script: &str) -> Result<Option<Value>, Error> {
        let res = self.runner.try_lock(script)?;
        Ok(res)
    }
}

// from Initial to Unlocked
impl<'a> From<Comrade<'a, Initial>> for Comrade<'a, Unlocked> {
    fn from(comrade: Comrade<'a>) -> Self {
        Comrade {
            // kvp_lock: comrade.kvp_lock,
            // kvp_unlock: comrade.kvp_unlock,
            runner: comrade.runner,
            _stage: std::marker::PhantomData,
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
pub mod tests {
    use super::*;
    use comrade_reference::Pairs;
    use std::collections::HashMap;

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

    // Helper functions that set up test data
    pub mod helpers {
        use super::*;

        // Autotrait test
        pub(crate) fn is_normal<T: Sized + Send + Sync + Unpin>() {}

        pub fn unlock_script(entry_key: &str, proof_key: &str) -> String {
            format!(
                r#"
                // push the serialized Entry as the message
                push("{entry_key}"); 

                // push the proof data
                push("{proof_key}");
            "#
            )
        }

        pub fn first_lock_script(entry_key: &str) -> String {
            format!(
                r#"
                // check the first key, which is ephemeral
                check_signature("/ephemeral", "{entry_key}") 
            "#
            )
        }

        pub fn other_lock_script(entry_key: &str) -> String {
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

        pub fn proof_data() -> Vec<u8> {
            hex::decode("b92483a6c006000100404819397f51b18bc6cffd1fff07afa33f7096c7a0c659590b077cc0ea5d6081d739512129becacb8e6997e6b7d18756299f515a822344ac2b6737979d5e5e6b03").unwrap()
        }

        pub fn pub_key() -> Vec<u8> {
            hex::decode("ba24ed010874657374206b657901012054d94d7b8a11d6581af4a14bc6451c7a23049018610f108c996968fe8fce9464").unwrap()
        }

        // Creates a setup with all necessary key-value pairs
        pub fn setup_test_data() -> (TestData, TestData, String) {
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

            // Set up the key-value pairs
            kvp_unlock.put(entry_key, &entry_data.to_vec().into());
            kvp_lock.put(entry_key, &entry_data.to_vec().into());
            kvp_unlock.put(proof_key, &proof_data.clone().into());
            kvp_lock.put(pubkey, &pub_key.into());

            // Return the configured test data and entry key
            (kvp_lock, kvp_unlock, entry_key.to_string())
        }
    }

    // The main test function that both native tests and WASM tests will call
    pub fn test_comrade_api() {
        use helpers::*;

        // Get our test setup
        let (kvp_lock, kvp_unlock, entry_key) = setup_test_data();
        let proof_key = "/entry/proof";

        // Create the scripts
        let unlock_script = unlock_script(&entry_key, proof_key);
        let first_lock = first_lock_script(&entry_key);
        let other_lock_script = other_lock_script(&entry_key);

        let mut comrade = Comrade::new(&kvp_lock, &kvp_unlock)
            .try_unlock(&unlock_script)
            .expect("Failed to unlock comrade");

        // check the lock scripts
        let locks = [first_lock, other_lock_script];

        // check the locks
        let mut count = 0;
        for lock in locks {
            if let Some(Value::Success(ct)) =
                comrade.try_lock(&lock).expect("Failed to lock comrade")
            {
                count = ct;
                break;
            }
        }

        // check the count
        assert_eq!(count, 2);
    }

    // Autotrait test for non-wasm32 targets
    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_autotraits() {
        // This is a dummy test to ensure that the crate runs in wasm32 target
        // and that the autotrait implementation is what is expected.
        helpers::is_normal::<Comrade<'_>>();
    }

    // This is the actual test that cargo test will run
    #[test]
    pub fn test_comrade_public_api() {
        test_comrade_api();
    }
}

#[cfg(target_arch = "wasm32")]
pub mod wasm_tests {
    pub fn run() {
        super::tests::test_comrade_api();
    }
}
