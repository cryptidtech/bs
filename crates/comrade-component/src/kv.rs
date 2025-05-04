use crate::bindings::comrade::api::{
    pairs::{self, get, put, Binary, Str},
    utils::log,
};
use comrade_reference::{Pairs, Value};

#[derive(Default, Clone, Debug)]
pub(crate) struct Current;

#[derive(Default, Clone, Debug)]
pub(crate) struct Proposed;

impl Pairs for Current {
    fn get(&self, key: &str) -> Option<Value> {
        get(pairs::Either::Current, key)
            .map(|v| v.into())
            .or_else(|| {
                log(&format!("Key not found: {key}"));
                None
            })
    }

    fn put(&mut self, key: &str, value: &Value) -> Option<Value> {
        log(&format!("Putting key: {key} value: {value:?}"));
        let val = put(pairs::Either::Current, key, &value.clone().into());
        Some(val.into())
    }
}

impl Pairs for Proposed {
    fn get(&self, key: &str) -> Option<Value> {
        get(pairs::Either::Proposed, key)
            .map(|v| v.into())
            .or_else(|| {
                log(&format!("Key not found: {key}"));
                None
            })
    }

    fn put(&mut self, key: &str, value: &Value) -> Option<Value> {
        log(&format!("Putting key: {key} value: {value:?}"));
        let val = put(pairs::Either::Proposed, key, &value.clone().into());
        Some(val.into())
    }
}

impl From<pairs::Value> for Value {
    fn from(value: crate::bindings::comrade::api::pairs::Value) -> Self {
        match value {
            pairs::Value::Str(Str { data, hint }) => Value::Str { hint, data },
            pairs::Value::Bin(Binary { data, hint }) => Value::Bin { hint, data },
            pairs::Value::Success(value) => Value::Success(value.try_into().unwrap()),
            pairs::Value::Failure(msg) => Value::Failure(msg),
        }
    }
}

impl From<Value> for pairs::Value {
    fn from(value: Value) -> Self {
        match value {
            Value::Str { hint, data } => pairs::Value::Str(Str { hint, data }),
            Value::Bin { hint, data } => pairs::Value::Bin(Binary { hint, data }),
            Value::Success(value) => pairs::Value::Success(value.try_into().unwrap()),
            Value::Failure(msg) => pairs::Value::Failure(msg),
        }
    }
}
