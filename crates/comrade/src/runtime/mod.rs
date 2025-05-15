//! Comrade Virutal runtime which manages running of the script using the chosen wasm component.
use crate::Error;
use comrade_reference::Value;

/// The "Direct" runtime is the default runtime for Comrade.
/// It uses the comrade-reference implementation directlt in rust
/// without any wasm component.
///
/// This way, we can run the entire workspace in rust without any wasm,
/// or as a wasm component itself.
mod direct;
pub(crate) use direct::Runner;

// NOTE: In the future, we could support other runtimes at this level,
// but it may only make sense to do so once there is demand for different backends.
// For example, the wasm runtime can use a wasm component layer to run the script
// instead of native rust code. This gives us a swappable interface in case a user
// wants a particular runtime for their use case which ours doesn't support.
// #[cfg(feature = "runtime-wasm")]
// mod layer;
// #[cfg(feature = "runtime-wasm")]
// pub(crate) use layer::Runner;
// Or other wasm runtimes can be used:
// mod wasmtime;
// mod wasm_i;
// mod wasmer;

/// Each runtime feature must implement the `Runtime` trait, to maintain a common interface.
pub trait Runtime {
    /// Sets the domain
    fn with_domain(&mut self, domain: &str);
    /// Run the script.
    fn try_unlock(&mut self, script: &str) -> Result<(), Error>;
    /// Get the top value from the context return stack.
    fn try_lock(&mut self, script: &str) -> Result<Option<Value>, Error>;
}
