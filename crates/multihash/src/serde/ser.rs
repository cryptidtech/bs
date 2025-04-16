// SPDX-License-Idnetifier: Apache-2.0
use crate::mh::{Multihash, SIGIL};
use multiutil::{EncodingInfo, Varbytes};
use serde::ser::{self, SerializeStruct};

/// Serialize instance of [`crate::Multihash`]
impl ser::Serialize for Multihash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            let mut ss = serializer.serialize_struct(SIGIL.as_str(), 2)?;
            ss.serialize_field("codec", &self.codec)?;
            ss.serialize_field(
                "hash",
                &Varbytes::encoded_new(Self::preferred_encoding(), self.hash.clone()),
            )?;
            ss.end()
        } else {
            let v: Vec<u8> = self.clone().into();
            serializer.serialize_bytes(v.as_slice())
        }
    }
}
