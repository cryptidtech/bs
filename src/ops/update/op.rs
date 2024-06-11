// SPDX-License-Identifier: FSL-1.1
use crate::{Error, error::UpdateError};
use provenance_log::{Key, Op, OpId, Value};
use std::convert::TryFrom;

/// the provenance log Op builder
#[derive(Clone, Debug, Default)]
pub struct Builder {
    /// the kind of op
    pub id: OpId,

    /// the key-path for the op
    pub key_path: Option<String>,

    /// the payload
    pub value: Option<Value>,
}

impl Builder {
    /// initialize the Op builder with the OpId
    pub fn new(id: OpId) -> Self {
        Self {
            id,
            .. Default::default()
        }
    }

    /// add the key
    pub fn with_key_path<S: AsRef<str>>(mut self, key_path: S) -> Self {
        self.key_path = Some(key_path.as_ref().to_string());
        self
    }

    /// add a string payload
    pub fn with_string_value<V: AsRef<str>>(mut self, value: V) -> Self {
        self.value = Some(Value::Str(value.as_ref().to_string()));
        self
    }

    /// add a data payload
    pub fn with_data_value<V: AsRef<[u8]>>(mut self, value: V) -> Self {
        self.value = Some(Value::Data(Vec::from(value.as_ref())));
        self
    }

    /// build the provenance log Op
    pub fn try_build(self) -> Result<Op, Error> {
        let key_path_string = self.key_path.ok_or(UpdateError::NoOpKeyPath)?;
        let key_path = Key::try_from(key_path_string)?;
        let op = match self.id {
            OpId::Noop => {
                Op::Noop(key_path)
            }
            OpId::Delete => {
                Op::Delete(key_path)
            }
            OpId::Update => {
                let value = self.value.ok_or(UpdateError::NoUpdateOpValue)?;
                Op::Update(key_path, value)
            }
        };
        Ok(op)
    }
}
