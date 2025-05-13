//! Use the comrrade-reference implementation of the runtime as a direct dependency.
mod logs;

use super::Runtime;
use comrade_reference::{Context, Pairs, Value};

/// The "Direct" runtime uses the comrade-reference implementation directly in rust
/// and is the default runtime for Comrade.
pub(crate) struct Runner<'un, 'lo> {
    pub(crate) context: Context<'un, 'lo>,
}

impl<'un, 'lo> Runner<'un, 'lo> {
    /// Creates a new Runner instance with the given lock and unlock pairs.
    pub fn new(kvp_lock: &'un impl Pairs, kvp_unlock: &'lo impl Pairs) -> Self {
        Self {
            context: Context::new(kvp_lock, kvp_unlock, &logs::Logger),
        }
    }
}

impl Runtime for Runner<'_, '_> {
    fn with_domain(&mut self, domain: &str) {
        self.context.domain = domain.to_string();
    }

    fn try_unlock(&mut self, script: &str) -> Result<(), crate::Error> {
        self.context.run(script)?;
        Ok(())
    }

    fn try_lock(&mut self, script: &str) -> Result<Option<Value>, crate::Error> {
        self.context.run(script)?;
        Ok(self.context.rstack())
    }
}
