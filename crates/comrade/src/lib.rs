//! Comrade is an execution engine for provenance log scripts.
//!
//! It requires a wasm-component plugin to run. A reference implementation is
//! provided in the `comrade-component` crate.
mod error;

use comrade_reference::Pairs;

/// Opinionated entry API for using Comrade.
/// Uses the comrade-component reference implementation by default,
/// and wasm_component_layer for runtime. Either can be substituted
/// with prefered alternatives as desired.
pub struct Comrade<C, P> {
    lock: C,
    unlock: P,
}

// API should be something like:
//
// let unlocked = Comrade::new(kvp_lock, kvp_unlock)
//     .with_domain("/")
//     .try_unlock(&unlock)?;
//
// let mut count = 0;
//
// for lock in locks {
//     if let Some(Value::Success(ct)) = unlocked.try_lock(lock)? {
//         count = ct;
//         break;
//     }
// }
//
// where the args impl Pairs

impl<C: Pairs, P: Pairs> Comrade<C, P> {
    pub fn new(lock: C, unlock: P) {}

    pub fn try_unlock(script: &str) {
        // something like:
        // vm::run(script)
    }
}
