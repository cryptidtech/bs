// SPDX-License-Identifier: FSL-1.1
use crate::{Value, ValueId};
use core::fmt;
use multiutil::{EncodedVarbytes, Varbytes};
use serde::{
    de::{EnumAccess, Error, SeqAccess, VariantAccess, Visitor},
    Deserialize, Deserializer,
};

/// Deserialize instance of [`crate::ValueId`]
impl<'de> Deserialize<'de> for ValueId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s: &str = Deserialize::deserialize(deserializer)?;
            Ok(ValueId::try_from(s).map_err(Error::custom)?)
        } else {
            let id: Varbytes = Deserialize::deserialize(deserializer)?;
            Ok(ValueId::try_from(id.to_inner().as_slice()).map_err(Error::custom)?)
        }
    }
}

/// Deserialize instance of [`crate::Value`]
impl<'de> Deserialize<'de> for Value {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const VARIANTS: &[&str] = &["nil", "str", "data"];

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Variant {
            Nil,
            Str,
            Data,
        }

        struct StrVisitor;

        impl<'de> Visitor<'de> for StrVisitor {
            type Value = Value;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "enum Value::Str(s)")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let s = seq
                    .next_element()?
                    .ok_or_else(|| Error::missing_field("string"))?;
                Ok(Value::Str(s))
            }
        }

        struct DataVisitor;

        impl<'de> Visitor<'de> for DataVisitor {
            type Value = Value;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "enum Value::Data(b)")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let b: EncodedVarbytes = seq
                    .next_element()?
                    .ok_or_else(|| Error::missing_field("data"))?;
                Ok(Value::Data(b.to_inner().to_inner()))
            }
        }

        struct ValueVisitor;

        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = Value;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "enum Value")
            }

            fn visit_enum<V>(self, e: V) -> Result<Self::Value, V::Error>
            where
                V: EnumAccess<'de>,
            {
                match e.variant()? {
                    (Variant::Nil, v) => {
                        v.unit_variant()?;
                        Ok(Value::Nil)
                    }
                    (Variant::Str, v) => Ok(v.tuple_variant(1, StrVisitor)?),
                    (Variant::Data, v) => Ok(v.tuple_variant(1, DataVisitor)?),
                }
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_enum("value", VARIANTS, ValueVisitor)
        } else {
            let b: &'de [u8] = Deserialize::deserialize(deserializer)?;
            Ok(Self::try_from(b).map_err(|e| Error::custom(e.to_string()))?)
        }
    }
}
