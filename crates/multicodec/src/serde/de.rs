// SPDX-License-Identifier: MIT or Apache-2.0
use crate::Codec;
use core::fmt;
use serde::{de, Deserialize, Deserializer};

/// Deserialize instances of [`crate::prelude::Codec`] from a varuint encoded
/// byte slice or a u8, u16, u32, or u64 value.
impl<'de> Deserialize<'de> for Codec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CodecVisitor;

        impl<'de> de::Visitor<'de> for CodecVisitor {
            type Value = Codec;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    fmt,
                    "borrowed str, str, String, borrowed byte array, byte buf, bytes, or sequence"
                )
            }

            // human readable

            // shortest lifetime
            #[inline]
            fn visit_borrowed_str<E>(self, s: &'de str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Self::Value::try_from(s).map_err(|e| de::Error::custom(e.to_string()))
            }

            // longest lifetime
            #[inline]
            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Self::Value::try_from(s).map_err(|e| de::Error::custom(e.to_string()))
            }

            // binary

            // shortest lifetime
            #[inline]
            fn visit_borrowed_bytes<E>(self, b: &'de [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Self::Value::try_from(b).map_err(|e| de::Error::custom(e.to_string()))
            }

            // longest lifetime
            #[inline]
            fn visit_bytes<E>(self, b: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Self::Value::try_from(b).map_err(|e| de::Error::custom(e.to_string()))
            }

            // binary / human readable

            // this typically only happens when there are bytes serialized into
            // a human readable format.
            #[inline]
            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: de::SeqAccess<'de>,
            {
                let mut v = Vec::new();
                while let Some(b) = seq.next_element()? {
                    v.push(b);
                }
                Self::Value::try_from(v.as_slice())
                    .map_err(|e| de::Error::custom(e.to_string()))
            }
        }

        deserializer.deserialize_any(CodecVisitor)
    }
}
