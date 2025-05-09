//! Uses crate wasm_component_layer to runt he wasm components.
//!
//! This crate is great because it gives us the ability to isomorphically run in the browser with
//! wasm_bindgen but without javascript, and also natively.
mod definitions;

use definitions::{
    either_enum, failure_variant, into_comp_value, into_core_value, success_variant, value_variant,
};

use super::Runtime;
use crate::Error;
use comrade_reference::{Pairable, Value};
use wasm_component_layer::{
    AsContextMut as _, Component, Engine, Func, FuncType, Instance, Linker, OptionType,
    OptionValue, ResourceOwn, Store, ValueType,
};

// wasmi layer for native targets
#[cfg(not(target_arch = "wasm32"))]
use wasmi_runtime_layer as runtime_layer;

// JS layer for the browser
#[cfg(target_arch = "wasm32")]
use js_wasm_runtime_layer as runtime_layer;

// C and P need to be bound by Send + Sync
pub(crate) struct Runner<C, P>
where
    C: Pairable,
    P: Pairable,
{
    /// The store for the component.
    store: Store<Data<C, P>, runtime_layer::Engine>,
    /// The instantiated component.
    instance: Instance,
    /// The constructed API resource for the instance
    api_resource: ResourceOwn,
}

trait Logger: Send + Sync + 'static {
    fn log(&self, message: &str);
}

struct TracingLogger;

impl Logger for TracingLogger {
    fn log(&self, message: &str) {
        tracing::debug!("{}", message);
    }
}

/// Internal struct for the store Data
struct Data<C, P>
where
    C: Pairable,
    P: Pairable,
{
    kvp_current: C,
    kvp_proposed: P,
    /// Functions that are only used interally
    logger: Box<dyn Logger>,
}

impl<C: Pairable, P: Pairable> Runner<C, P> {
    /// Create a new runner with a tracing logger.
    pub(crate) fn new(kvp_current: C, kvp_proposed: P) -> Self {
        // Use default logger
        Self::new_with_logger(kvp_current, kvp_proposed, Box::new(TracingLogger))
    }

    /// Create a new runner.
    // #[cfg(test)]
    fn new_with_logger(kvp_current: C, kvp_proposed: P, logger: Box<dyn Logger>) -> Self {
        // target/wasm32-unknown-unknown/release/comrade_component.wasm
        let bytes: &[u8] = include_bytes!(
            "../../../../../target/wasm32-unknown-unknown/release/comrade_component.wasm"
        );

        // Create a new engine for instantiating a component.
        let engine = Engine::new(runtime_layer::Engine::default());

        // Create a store for managing WASM data and any custom user-defined state.
        let mut store = Store::new(
            &engine,
            Data {
                kvp_current,
                kvp_proposed,
                logger,
            },
        );

        tracing::debug!("Created store, loading bytes.",);
        // Parse the component bytes and load its imports and exports.
        let component = Component::new(&engine, &bytes).unwrap();

        tracing::debug!("Loaded bytes");

        // Create a linker that will be used to resolve the component's imports, if any.
        let mut linker = Linker::default();

        let host_interface = linker
            .define_instance("comrade:api/utils".try_into().unwrap())
            .unwrap();

        host_interface
            .define_func(
                "log",
                Func::new(
                    &mut store,
                    FuncType::new([ValueType::String], []),
                    move |store, params, _results| {
                        if let wasm_component_layer::Value::String(s) = &params[0] {
                            store.data().logger.log(s.to_string().as_str());
                        }
                        Ok(())
                    },
                ),
            )
            .unwrap();

        // func "random-byte" is defined in the host interface
        host_interface
            .define_func(
                "random-byte",
                Func::new(
                    &mut store,
                    FuncType::new([], [ValueType::U8]),
                    move |_store, _params, results| {
                        let mut random = [0u8; 1];
                        getrandom::fill(&mut random)?;
                        results[0] = wasm_component_layer::Value::U8(random[0]);
                        Ok(())
                    },
                ),
            )
            .unwrap();

        let pairs_interface = linker
            .define_instance("comrade:api/pairs".try_into().unwrap())
            .unwrap();

        // get(choice: either, key: string) -> option<value>
        // gets either the current or proposed
        pairs_interface
            .define_func(
                "get",
                Func::new(
                    &mut store,
                    FuncType::new(
                        [ValueType::Enum(either_enum()), ValueType::String],
                        [ValueType::Option(OptionType::new(ValueType::Variant(
                            value_variant(),
                        )))],
                    ),
                    move |store, params, results| {
                        if let wasm_component_layer::Value::Enum(choice) = &params[0] {
                            if let wasm_component_layer::Value::String(key) = &params[1] {
                                let data = store.data();
                                let value = match choice.discriminant() {
                                    0 => {
                                        tracing::debug!("[TestLog] get current");
                                        &data.kvp_current.get(key.to_string().as_str())
                                    }
                                    1 => {
                                        tracing::debug!("[TestLog] get proposed");
                                        &data.kvp_proposed.get(key.to_string().as_str())
                                    }
                                    _ => panic!("Invalid choice"),
                                };
                                tracing::debug!("\n[TestLog] get({:?}) = {:?}\n", key, value);
                                results[0] = match value {
                                    Some(v) => {
                                        let value = into_comp_value(v.clone()).unwrap();
                                        wasm_component_layer::Value::Option(OptionValue::new(
                                            OptionType::new(ValueType::Variant(value_variant())),
                                            Some(value),
                                        )?)
                                    }
                                    None => wasm_component_layer::Value::Option(OptionValue::new(
                                        OptionType::new(ValueType::Variant(value_variant())),
                                        None,
                                    )?),
                                };
                            } else {
                                panic!("Expected String, found {:?}", params[1]);
                            }
                        };
                        Ok(())
                    },
                ),
            )
            .unwrap();

        // put is similar to get, except it mutates the current or proposed value witht he given value
        // and key
        // it returns success or failure
        pairs_interface
            .define_func(
                "put",
                Func::new(
                    &mut store,
                    FuncType::new(
                        [
                            ValueType::Enum(either_enum()),
                            ValueType::String,
                            ValueType::Variant(value_variant()),
                        ],
                        [ValueType::Variant(value_variant())],
                    ),
                    move |mut store, params, results| {
                        if let wasm_component_layer::Value::Enum(choice) = &params[0] {
                            if let wasm_component_layer::Value::String(key) = &params[1] {
                                let data = store.data_mut();
                                let value = into_core_value(params[2].clone()).unwrap();
                                // TODO: Store return value
                                let v = match choice.discriminant() {
                                    0 => {
                                        &mut data.kvp_current.put(key.to_string().as_str(), &value)
                                    }
                                    1 => {
                                        &mut data.kvp_proposed.put(key.to_string().as_str(), &value)
                                    }
                                    _ => panic!("Invalid enum choice, must be current or proposed"),
                                };
                                results[0] = success_variant(0);
                            } else {
                                results[0] = failure_variant(format!(
                                    "Expected String, found {:?}",
                                    params[1]
                                ));
                            }
                        };
                        Ok(())
                    },
                ),
            )
            .unwrap();

        // Instantiate the component with the linker and store.
        let instance = linker.instantiate(&mut store, &component).unwrap();

        // Construct
        let exports = instance.exports();
        let api_export_instance = exports
            .instance(&"comrade:api/api".try_into().unwrap())
            .unwrap();

        // Call the resource constructor
        let resource_constructor = api_export_instance.func("[constructor]api").unwrap();

        let arguments = &[];
        let mut results = vec![wasm_component_layer::Value::Bool(false)];

        resource_constructor
            .call(&mut store, arguments, &mut results)
            .unwrap();

        let api_resource = match results[0] {
            wasm_component_layer::Value::Own(ref resource) => resource.clone(),
            _ => panic!("Unexpected result type"),
        };

        Self {
            store,
            instance,
            api_resource,
        }
    }
}

impl<C: Pairable, P: Pairable> Runtime for Runner<C, P> {
    fn try_unlock(&mut self, unlock: &str) -> Result<(), Error> {
        let api_export_instance = self
            .instance
            .exports()
            .instance(&"comrade:api/api".try_into().unwrap())
            .unwrap();

        let borrowed_api = self
            .api_resource
            .borrow(self.store.as_context_mut())
            .unwrap();

        let unlock_args = vec![
            wasm_component_layer::Value::Borrow(borrowed_api.clone()),
            wasm_component_layer::Value::String(unlock.into()),
        ];

        let try_unlock = api_export_instance.func("[method]api.try-unlock").unwrap();

        // Call the try_unlock method
        let mut results = vec![wasm_component_layer::Value::Bool(false)];
        try_unlock
            .call(&mut self.store, &unlock_args, &mut results)
            .unwrap();
        Ok(())
    }

    fn try_lock(&self) -> Result<Option<Value>, Error> {
        // call try_lock on the instance
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use comrade_reference::Pairs;

    use super::*;
    use crate::runtime::Runtime;

    struct TestLogger {
        messages: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl TestLogger {
        fn new() -> Self {
            Self {
                messages: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn get_messages(&self) -> Vec<String> {
            let lock = self.messages.lock().unwrap();
            lock.clone()
        }

        fn clear_messages(&self) {
            let mut lock = self.messages.lock().unwrap();
            lock.clear();
        }
    }

    impl Logger for TestLogger {
        fn log(&self, message: &str) {
            let mut messages = self.messages.lock().unwrap();
            messages.push(message.to_string());
        }
    }

    impl Clone for TestLogger {
        fn clone(&self) -> Self {
            Self {
                messages: Arc::clone(&self.messages),
            }
        }
    }

    impl<C: Pairable, P: Pairable> Runner<C, P> {
        // Helper for tests that returns both the runner and the logger
        fn new_for_test(kvp_current: C, kvp_proposed: P) -> (Self, TestLogger) {
            let test_logger = TestLogger::new();
            let logger_box: Box<dyn Logger> = Box::new(test_logger.clone());

            // Force a test message to verify logging works
            logger_box.log("Test log system");

            let runner = Self::new_with_logger(kvp_current, kvp_proposed, logger_box);
            (runner, test_logger)
        }
    }

    #[derive(Clone, Default, Debug)]
    struct TestData(HashMap<String, Value>);

    impl Pairs for TestData {
        fn get(&self, key: &str) -> Option<Value> {
            self.0.get(key).cloned()
        }

        fn put(&mut self, key: &str, value: &Value) -> Option<Value> {
            self.0.insert(key.to_string(), value.clone())
        }
    }

    #[test]
    fn test_layer_runner() {
        let mut runner = Runner::new(TestData::default(), TestData::default());
        assert_eq!(runner.try_lock(), Ok(None));
        assert!(runner.try_unlock("test").is_ok());
    }

    #[test]
    fn test_log() {
        // When we call the consturctor for the reference impl wasm bytes,
        // we should get log("Creating new Component");

        let (runner, test_logger) = Runner::new_for_test(TestData::default(), TestData::default());

        let logs = test_logger.get_messages();

        assert!(logs
            .iter()
            .any(|msg| msg.contains("Creating new Component")));
    }
}
