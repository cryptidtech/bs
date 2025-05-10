#[allow(warnings)]
mod bindings;

mod kv;
mod logger;
mod random;

use crate::{
    kv::{Current, Proposed},
    logger::Logger,
};
use bindings::comrade::api::pairs;
use bindings::comrade::api::utils::log;
use bindings::exports::comrade::api::api::Guest;
use bindings::exports::comrade::api::api::GuestApi;
use comrade_reference::Context;
use std::cell::RefCell;

struct Api {
    context: RefCell<Context<'static>>,
}

impl Guest for Api {
    type Api = Self;
}

impl GuestApi for Api {
    fn new() -> Self {
        log("Creating new Component");

        Self {
            context: RefCell::new(Context::new(&Current, &Proposed, &Logger)),
        }
    }

    fn try_unlock(&self, unlock: String) -> Result<(), String> {
        log("[component] try_unlock(..)");
        self.context.borrow_mut().run(&unlock).map_err(|e| {
            log(&format!("Error running unlock script: {e}"));
            format!("Error running unlock script: {e}")
        })?;
        Ok(())
    }

    fn try_lock(&self, lock: String) -> Result<Option<pairs::Value>, String> {
        log(&format!("try_lock script: {lock}"));
        self.context.borrow_mut().run(&lock).map_err(|e| {
            log(&format!("Error running lock script: {e}"));
            format!("Error running lock script: {e}")
        })?;
        // return rstack
        let rstack = self.context.borrow_mut().rstack();
        Ok(rstack.map(|v| v.into()))
    }
}

bindings::export!(Api with_types_in bindings);
