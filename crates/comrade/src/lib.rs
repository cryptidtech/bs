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
        self.runner.try_unlock(script)?;
        // check the context retrun stack top, return the result
        let res = self.runner.try_lock()?;
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
