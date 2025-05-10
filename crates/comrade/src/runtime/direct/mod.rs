//! Use the comrrade-reference implementation of the runtime as a direct dependency.
mod logs;

use super::Runtime;
use comrade_reference::{Context, Pairable, Value};

/// The "Direct" runtime uses the comrade-reference implementation directly in rust
/// and is the default runtime for Comrade.
pub(crate) struct Runner<'a> {
    pub(crate) context: Context<'a>,
}

impl<'a> Runner<'a> {
    /// Creates a new Runner instance with the given lock and unlock pairs.
    pub fn new(kvp_lock: &'a impl Pairable, kvp_unlock: &'a impl Pairable) -> Self {
        Self {
            context: Context::new(kvp_lock, kvp_unlock, &logs::Logger),
        }
    }
}

impl<'a> Runtime for Runner<'a> {
    fn try_unlock(&mut self, script: &str) -> Result<(), crate::Error> {
        self.context.run(script)?;
        Ok(())
    }

    fn try_lock(&mut self, script: &str) -> Result<Option<Value>, crate::Error> {
        self.context.run(script)?;
        let rstack = self.context.rstack();
        Ok(rstack.map(|v| v.into()))
    }
}
