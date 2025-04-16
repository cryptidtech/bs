// SPDX-License-Identifier: MIT or Apache-2.0
use crate::Codec;
use serde::ser;

/// Serialize instances of [`crate::prelude::Codec`] into varuint encoded bytes
impl ser::Serialize for Codec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            let s: &str = (*self).into();
            serializer.serialize_str(s)
        } else {
            let v: Vec<u8> = (*self).into();
            serializer.serialize_bytes(v.as_slice())
        }
    }
}
