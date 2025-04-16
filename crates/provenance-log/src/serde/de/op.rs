// SPDX-License-Identifier: FSL-1.1
use crate::{Op, OpId};
use core::fmt;
use multiutil::Varbytes;
use serde::{
    de::{EnumAccess, Error, SeqAccess, VariantAccess, Visitor},
    Deserialize, Deserializer,
};

/// Deserialize instance of [`crate::OpId`]
impl<'de> Deserialize<'de> for OpId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s: &str = Deserialize::deserialize(deserializer)?;
            Ok(OpId::try_from(s).map_err(Error::custom)?)
        } else {
            let id: Varbytes = Deserialize::deserialize(deserializer)?;
            Ok(OpId::try_from(id.to_inner().as_slice()).map_err(Error::custom)?)
        }
    }
}

/// Deserialize instance of [`crate::Op`]
impl<'de> Deserialize<'de> for Op {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const VARIANTS: &[&str] = &["noop", "delete", "update"];

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Variant {
            Noop,
            Delete,
            Update,
        }

        struct NoopVisitor;

        impl<'de> Visitor<'de> for NoopVisitor {
            type Value = Op;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "enum Op::Noop(key)")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let key = seq
                    .next_element()?
                    .ok_or_else(|| Error::missing_field("key"))?;
                Ok(Op::Noop(key))
            }
        }

        struct DeleteVisitor;

        impl<'de> Visitor<'de> for DeleteVisitor {
            type Value = Op;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "enum Op::Delete(key)")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let key = seq
                    .next_element()?
                    .ok_or_else(|| Error::missing_field("key"))?;
                Ok(Op::Delete(key))
            }
        }

        struct UpdateVisitor;

        impl<'de> Visitor<'de> for UpdateVisitor {
            type Value = Op;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "enum Op::Update(key, value)")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let key = seq
                    .next_element()?
                    .ok_or_else(|| Error::missing_field("key"))?;
                let value = seq
                    .next_element()?
                    .ok_or_else(|| Error::missing_field("value"))?;
                Ok(Op::Update(key, value))
            }
        }

        struct OpVisitor;

        impl<'de> Visitor<'de> for OpVisitor {
            type Value = Op;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "enum Op")
            }

            fn visit_enum<V>(self, e: V) -> Result<Self::Value, V::Error>
            where
                V: EnumAccess<'de>,
            {
                match e.variant()? {
                    (Variant::Noop, v) => Ok(v.tuple_variant(1, NoopVisitor)?),
                    (Variant::Delete, v) => Ok(v.tuple_variant(1, DeleteVisitor)?),
                    (Variant::Update, v) => Ok(v.tuple_variant(2, UpdateVisitor)?),
                }
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_enum("op", VARIANTS, OpVisitor)
        } else {
            let b: &'de [u8] = Deserialize::deserialize(deserializer)?;
            Ok(Self::try_from(b).map_err(|e| Error::custom(e.to_string()))?)
        }
    }
}
