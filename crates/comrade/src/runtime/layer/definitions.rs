use crate::Pairs;
use std::collections::HashMap;
use wasm_component_layer::*;

pub fn list_data() -> ValueType {
    ValueType::List(ListType::new(ValueType::U8))
}

pub fn binary_rec_ty() -> RecordType {
    RecordType::new(
        None,
        vec![("data", list_data()), ("hint", ValueType::String)],
    )
    .unwrap()
}

pub fn str_rec_ty() -> RecordType {
    RecordType::new(
        None,
        vec![("data", ValueType::String), ("hint", ValueType::String)],
    )
    .unwrap()
}

/// Vlaue variant type is either, binary, str, success(u32), or failure(String)
pub fn value_variant() -> VariantType {
    VariantType::new(
        None,
        vec![
            VariantCase::new("bin", Some(ValueType::Record(binary_rec_ty()))),
            VariantCase::new("str", Some(ValueType::Record(str_rec_ty()))),
            VariantCase::new("success", Some(ValueType::U32)),
            VariantCase::new("failure", Some(ValueType::String)),
        ],
    )
    .unwrap()
}

/// Represents either: a current or proposed
pub fn either_enum() -> EnumType {
    EnumType::new(None, vec!["current", "proposed"]).unwrap()
}

pub fn bin_variant(data: Vec<u8>, hint: String) -> Value {
    Value::Variant(
        Variant::new(
            value_variant(),
            0,
            Some(Value::Record(
                Record::new(
                    binary_rec_ty(),
                    vec![
                        (
                            "data",
                            Value::List(
                                List::new(
                                    ListType::new(ValueType::U8),
                                    data.iter().map(|b| Value::U8(*b)).collect::<Vec<Value>>(),
                                )
                                .unwrap(),
                            ),
                        ),
                        ("hint", Value::String(hint.into())),
                    ],
                )
                .unwrap(),
            )),
        )
        .unwrap(),
    )
}

pub fn str_variant(data: String, hint: String) -> Value {
    Value::Variant(
        Variant::new(
            value_variant(),
            1,
            Some(Value::Record(
                Record::new(
                    str_rec_ty(),
                    vec![
                        ("data", Value::String(data.into())),
                        ("hint", Value::String(hint.into())),
                    ],
                )
                .unwrap(),
            )),
        )
        .unwrap(),
    )
}

pub fn failure_variant(msg: String) -> Value {
    Value::Variant(Variant::new(value_variant(), 3, Some(Value::String(msg.into()))).unwrap())
}

/// Success variant
pub fn success_variant(code: u32) -> Value {
    Value::Variant(Variant::new(value_variant(), 2, Some(Value::U32(code))).unwrap())
}

#[derive(Clone, Default, Debug)]
pub struct ContextPairs {
    pairs: HashMap<String, crate::Value>,
}

impl Pairs for ContextPairs {
    fn get(&self, key: &str) -> Option<crate::Value> {
        self.pairs.get(key).cloned()
    }

    fn put(&mut self, key: &str, value: &crate::Value) -> Option<crate::Value> {
        self.pairs.insert(key.to_string(), value.clone())
    }
}

/// From crate::Value to wasm_component_layer::Value
pub fn into_comp_value(value: crate::Value) -> Result<wasm_component_layer::Value, String> {
    match value {
        crate::Value::Bin { hint, data } => {
            // Create the record first
            let record = Record::new(
                binary_rec_ty(),
                vec![
                    (
                        "data",
                        Value::List(
                            List::new(
                                ListType::new(ValueType::U8),
                                data.iter().map(|b| Value::U8(*b)).collect::<Vec<Value>>(),
                            )
                            .unwrap(),
                        ),
                    ),
                    ("hint", Value::String(hint.into())),
                ],
            )
            .unwrap();

            // Then wrap it in the variant (bin is case 0)
            Ok(Value::Variant(
                Variant::new(value_variant(), 0, Some(Value::Record(record))).unwrap(),
            ))
        }
        crate::Value::Str { hint, data } => {
            // Create the record first
            let record = Record::new(
                str_rec_ty(),
                vec![
                    ("data", Value::String(data.into())),
                    ("hint", Value::String(hint.into())),
                ],
            )
            .unwrap();

            // Then wrap it in the variant (str is case 1)
            Ok(Value::Variant(
                Variant::new(value_variant(), 1, Some(Value::Record(record))).unwrap(),
            ))
        }
        _ => Err(format!(
            "Cannot convert {:?} to wasm_component_layer::Value",
            value
        )),
    }
}

/// Convert from wasm_component_layer::Value to crate::Value
pub fn into_core_value(value: wasm_component_layer::Value) -> Result<crate::Value, String> {
    match value {
        wasm_component_layer::Value::Record(record) => {
            if let Some(Value::String(hint)) = record.field("hint") {
                if let Some(Value::List(list)) = record.field("data") {
                    let data: Vec<u8> = list
                        .iter()
                        .map(|v| match v {
                            Value::U8(b) => Ok(b),
                            _ => Err(format!("Expected U8, found {:?}", v)),
                        })
                        .collect::<Result<Vec<u8>, String>>()?;
                    return Ok(crate::Value::Bin {
                        hint: hint.to_string(),
                        data,
                    });
                }
            }
            Err(format!("Invalid record: {:?}", record))
        }
        _ => Err(format!("Cannot convert {:?} to crate::Value", value)),
    }
}
