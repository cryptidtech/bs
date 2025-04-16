// SPDX-License-Identifier: FSL-1.1
use crate::{api, error::VmError, Context, Error, Instance};
use wasmtime::{Config, Engine, Linker, Module, Store};

/// Builder type for constructing WacVm instances
#[derive(Default)]
pub struct Builder<'a>
{
    fuel: Option<u64>,
    bytes: Vec<u8>,
    context: Option<Context<'a>>,
}

impl<'a> Builder<'a>
{
    /// create a new builder
    pub fn new() -> Self {
        Self {
            fuel: None,
            bytes: Vec::default(),
            context: None,
        }
    }

    /// Enables the use of fuel and establishes the fuel limit for the execution
    pub fn with_fuel(mut self, fuel: u64) -> Self {
        self.fuel = Some(fuel);
        self
    }

    /// Initializes the [`Instance`] with the bytes to execute
    pub fn with_bytes(mut self, bytes: impl AsRef<[u8]>) -> Self {
        self.bytes = bytes.as_ref().to_vec();
        self
    }

    /// Add the context for the application state
    pub fn with_context(mut self, context: Context<'a>) -> Self {
        self.context = Some(context);
        self
    }

    /// Tries to build the [`Instance`] from the builder configuration
    pub fn try_build(self) -> Result<Instance<'a>, Error> {
        // configure the engine
        let mut config = Config::default();
        config.consume_fuel(self.fuel.is_some());
        let engine = Engine::new(&config).map_err(|e| Error::Wasmtime(e.to_string()))?;

        // try to compile the script
        let aot = engine.precompile_module(&self.bytes).map_err(|e| Error::Wasmtime(e.to_string()))?;

        // configure the module
        let module = unsafe { Module::deserialize(&engine, aot).map_err(|e| Error::Wasmtime(e.to_string()))? };

        // get the context
        let context = match self.context {
            Some(ctx) => ctx,
            _ => return Err(VmError::MissingContext.into()),
        };

        // configure the store
        let mut store = Store::new(&engine, context);
        if let Some(fuel) = self.fuel {
            store
                .set_fuel(fuel)
                .map_err(|e| Error::Wasmtime(e.to_string()))?;
        }

        // configure the limiter
        store.limiter(|state| &mut state.limiter);

        // configure the linker
        let mut linker = Linker::new(&engine);

        // add the Wacc functions
        api::add_to_linker(&engine, &mut linker)?;

        // build the instance
        Ok(Instance {
            linker,
            module,
            store,
        })
    }
}
