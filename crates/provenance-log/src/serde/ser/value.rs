// SPDX-License-Identifier: FSL-1.1
use crate::{Value, ValueId};
use multiutil::{EncodingInfo, Varbytes};
use serde::ser::{self, SerializeTupleVariant};

/// Serialize instance of [`crate::ValueId`]
impl ser::Serialize for ValueId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.as_str())
        } else {
            Varbytes(self.clone().into()).serialize(serializer)
        }
    }
}

/// Serialize instance of [`crate::Value`]
impl ser::Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            match self {
                Self::Nil => serializer.serialize_unit_variant(
                    "value",
                    ValueId::Nil.code() as u32,
                    ValueId::Nil.as_str(),
                ),
                Self::Str(s) => {
                    let mut ss = serializer.serialize_tuple_variant(
                        "value",
                        ValueId::Str.code() as u32,
                        ValueId::Str.as_str(),
                        1,
                    )?;
                    ss.serialize_field(&s)?;
                    ss.end()
                }
                Self::Data(b) => {
                    let mut ss = serializer.serialize_tuple_variant(
                        "value",
                        ValueId::Data.code() as u32,
                        ValueId::Data.as_str(),
                        1,
                    )?;
                    ss.serialize_field(&Varbytes::encoded_new(self.encoding(), b.clone()))?;
                    ss.end()
                }
            }
        } else {
            let v: Vec<u8> = self.clone().into();
            serializer.serialize_bytes(v.as_slice())
        }
    }
}
