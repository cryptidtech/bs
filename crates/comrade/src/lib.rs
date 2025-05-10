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

/// Polyfills required to ensure getrandom works in wasm32 target for v0.3
#[cfg(target_arch = "wasm32")]
mod random;

// Using the same trait out of convenience, the Pairs trait is very basic
use comrade_reference::{Pairable, Pairs, Value};
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
pub struct Comrade<C: Pairable, P: Pairable, Stage = Initial> {
    // /// The key-value pairs asociated with the lock
    // kvp_lock: C,
    // /// The key-value pairs asociated with the unlock
    // kvp_unlock: P,
    runner: runtime::Runner<C, P>,
    _stage: std::marker::PhantomData<Stage>,
}

impl<C: Pairable, P: Pairable> Comrade<C, P> {
    /// Creates a new Comrade instance with the given lock and unlock pairs.
    pub fn new(kvp_lock: C, kvp_unlock: P) -> Self {
        Comrade {
            runner: runtime::Runner::new(kvp_lock, kvp_unlock),
            // kvp_lock,
            // kvp_unlock,
            _stage: std::marker::PhantomData,
        }
    }

    /// Tries to unlock the comrade with the given script.
    /// Will return an error if the script fails to run.
    pub fn try_unlock(mut self, script: &str) -> Result<Comrade<C, P, Unlocked>, Error> {
        self.runner.try_unlock(script)?;
        Ok(self.into())
    }
}

// try_lock can only be called on an Unlocked Comrade
impl<C: Pairable, P: Pairable> Comrade<C, P, Unlocked> {
    /// Tries to lock the comrade with the given script.
    /// Will return an error if the script fails to run.
    pub fn try_lock(&mut self, script: &str) -> Result<Option<Value>, Error> {
        let res = self.runner.try_lock(script)?;
        Ok(res)
    }
}

// from Initial to Unlocked
impl<C: Pairable, P: Pairable> From<Comrade<C, P, Initial>> for Comrade<C, P, Unlocked> {
    fn from(comrade: Comrade<C, P>) -> Self {
        Comrade {
            // kvp_lock: comrade.kvp_lock,
            // kvp_unlock: comrade.kvp_unlock,
            runner: comrade.runner,
            _stage: std::marker::PhantomData,
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub mod wasm_tests {
    pub fn run() {
        super::tests::test_comrade_api();
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
    #[cfg(any(target_arch = "wasm32", test))]
    fn proof_data() -> Vec<u8> {
        hex::decode("b92483a6c006000100404819397f51b18bc6cffd1fff07afa33f7096c7a0c659590b077cc0ea5d6081d739512129becacb8e6997e6b7d18756299f515a822344ac2b6737979d5e5e6b03").unwrap()
    }

    #[cfg(any(target_arch = "wasm32", test))]
    fn pub_key() -> Vec<u8> {
        hex::decode("ba24ed010874657374206b657901012054d94d7b8a11d6581af4a14bc6451c7a23049018610f108c996968fe8fce9464").unwrap()
    }

    #[test]
    pub fn test_comrade() {
        test_comrade_api();
    }

    pub fn test_comrade_api() {
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
}
