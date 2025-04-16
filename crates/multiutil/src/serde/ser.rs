// SPDX-License-Idnetifier: Apache-2.0
use crate::{BaseEncoded, BaseEncoder, EncodingInfo, Varbytes, Varuint};
use multitrait::prelude::EncodeInto;
use serde::ser;

/// Serialize instance of [`crate::BaseEncoded`] into
impl<T, Enc> ser::Serialize for BaseEncoded<T, Enc>
where
    T: ser::Serialize + EncodingInfo + Clone + Into<Vec<u8>>,
    Enc: BaseEncoder,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            self.to_string().as_str().serialize(serializer)
        } else {
            (self.base.code(), self.t.clone()).serialize(serializer)
        }
    }
}

/// Serialize instance of [`crate::Varuint`]
impl<T> ser::Serialize for Varuint<T>
where
    T: EncodeInto,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_bytes(self.0.encode_into().as_slice())
    }
}

/// Serialize instance of [`crate::Varbytes`]
impl ser::Serialize for Varbytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let mut v = self.0.len().encode_into();
        v.append(&mut self.0.clone());
        serializer.serialize_bytes(v.as_slice())
    }
}
