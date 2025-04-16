// SPDX-License-Identifier: FSL-1.1
use crate::{script::SIGIL, Script, ScriptId};
use multiutil::{EncodingInfo, Varbytes};
use serde::ser::{self, SerializeTupleVariant};

/// Serialize instance of [`crate::ScriptId`]
impl ser::Serialize for ScriptId {
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

/// Serialize instance of [`crate::Script`]
impl ser::Serialize for Script {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            match self {
                Self::Bin(p, b) => {
                    let mut ss = serializer.serialize_tuple_variant(
                        SIGIL.as_str(),
                        ScriptId::Bin.code() as u32,
                        ScriptId::Bin.as_str(),
                        2,
                    )?;
                    ss.serialize_field(&p)?;
                    ss.serialize_field(&Varbytes::encoded_new(self.encoding(), b.clone()))?;
                    ss.end()
                }
                Self::Code(p, s) => {
                    let mut ss = serializer.serialize_tuple_variant(
                        SIGIL.as_str(),
                        ScriptId::Code.code() as u32,
                        ScriptId::Code.as_str(),
                        2,
                    )?;
                    ss.serialize_field(&p)?;
                    ss.serialize_field(&s)?;
                    ss.end()
                }
                Self::Cid(p, cid) => {
                    let mut ss = serializer.serialize_tuple_variant(
                        SIGIL.as_str(),
                        ScriptId::Cid.code() as u32,
                        ScriptId::Cid.as_str(),
                        2,
                    )?;
                    ss.serialize_field(&p)?;
                    ss.serialize_field(&cid)?;
                    ss.end()
                }
            }
        } else {
            let v: Vec<u8> = self.clone().into();
            serializer.serialize_bytes(v.as_slice())
        }
    }
}
