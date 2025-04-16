// SPDX-License-Identifier: FSL-1.1
use crate::{Op, OpId};
use multiutil::Varbytes;
use serde::ser::{self, SerializeTupleVariant};

/// Serialize instance of [`crate::OpId`]
impl ser::Serialize for OpId {
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

/// Serialize instance of [`crate::Op`]
impl ser::Serialize for Op {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            match self {
                Self::Noop(key) => {
                    let mut ss = serializer.serialize_tuple_variant(
                        "op",
                        OpId::Noop.code() as u32,
                        OpId::Noop.as_str(),
                        1,
                    )?;
                    ss.serialize_field(&key)?;
                    ss.end()
                }
                Self::Delete(key) => {
                    let mut ss = serializer.serialize_tuple_variant(
                        "op",
                        OpId::Delete.code() as u32,
                        OpId::Delete.as_str(),
                        1,
                    )?;
                    ss.serialize_field(&key)?;
                    ss.end()
                }
                Self::Update(key, value) => {
                    let mut ss = serializer.serialize_tuple_variant(
                        "op",
                        OpId::Update.code() as u32,
                        OpId::Update.as_str(),
                        2,
                    )?;
                    ss.serialize_field(&key)?;
                    ss.serialize_field(&value)?;
                    ss.end()
                }
            }
        } else {
            let v: Vec<u8> = self.clone().into();
            serializer.serialize_bytes(v.as_slice())
        }
    }
}
