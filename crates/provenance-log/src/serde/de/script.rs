// SPDX-License-Identifier: FSL-1.1
use crate::{Key, script::SIGIL, Script, ScriptId};
use core::fmt;
use multicid::Cid;
use multiutil::{EncodedVarbytes, Varbytes};
use serde::{
    de::{EnumAccess, Error, SeqAccess, VariantAccess, Visitor},
    Deserialize, Deserializer,
};

/// Deserialize instance of [`crate::ScriptId`]
impl<'de> Deserialize<'de> for ScriptId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s: &str = Deserialize::deserialize(deserializer)?;
            Ok(ScriptId::try_from(s).map_err(Error::custom)?)
        } else {
            let id: Varbytes = Deserialize::deserialize(deserializer)?;
            Ok(ScriptId::try_from(id.to_inner().as_slice()).map_err(Error::custom)?)
        }
    }
}

/// Deserialize instance of [`crate::Script`]
impl<'de> Deserialize<'de> for Script {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const VARIANTS: &[&str] = &["bin", "code", "cid"];

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Variant {
            Bin,
            Code,
            Cid,
        }

        struct BinVisitor;

        impl<'de> Visitor<'de> for BinVisitor {
            type Value = Script;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "enum Script::Bin(path, bin)")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let p: Key = seq
                    .next_element()?
                    .ok_or_else(|| Error::missing_field("path"))?;
                let s: &str = seq
                    .next_element()?
                    .ok_or_else(|| Error::missing_field("bin"))?;
                let v = EncodedVarbytes::try_from(s).map_err(Error::custom)?;
                Ok(Script::Bin(p, v.to_inner().to_vec()))
            }
        }

        struct CodeVisitor;

        impl<'de> Visitor<'de> for CodeVisitor {
            type Value = Script;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "enum Script::Code(path, str)")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let p: Key = seq
                    .next_element()?
                    .ok_or_else(|| Error::missing_field("path"))?;
                let s: String = seq
                    .next_element()?
                    .ok_or_else(|| Error::missing_field("code"))?;
                Ok(Script::Code(p, s))
            }
        }

        struct CidVisitor;

        impl<'de> Visitor<'de> for CidVisitor {
            type Value = Script;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "enum Script::Cid(path, cid)")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let p: Key = seq
                    .next_element()?
                    .ok_or_else(|| Error::missing_field("path"))?;
                let cid: Cid = seq
                    .next_element()?
                    .ok_or_else(|| Error::missing_field("cid"))?;
                Ok(Script::Cid(p, cid))
            }
        }

        struct ScriptVisitor;

        impl<'de> Visitor<'de> for ScriptVisitor {
            type Value = Script;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "enum Script")
            }

            fn visit_enum<V>(self, e: V) -> Result<Self::Value, V::Error>
            where
                V: EnumAccess<'de>,
            {
                match e.variant()? {
                    (Variant::Bin, v) => Ok(v.tuple_variant(2, BinVisitor)?),
                    (Variant::Code, v) => Ok(v.tuple_variant(2, CodeVisitor)?),
                    (Variant::Cid, v) => Ok(v.tuple_variant(2, CidVisitor)?),
                }
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_enum(SIGIL.as_str(), VARIANTS, ScriptVisitor)
        } else {
            let b: &'de [u8] = Deserialize::deserialize(deserializer)?;
            Ok(Self::try_from(b).map_err(|e| Error::custom(e.to_string()))?)
        }
    }
}
