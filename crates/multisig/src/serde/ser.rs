// SPDX-License-Idnetifier: Apache-2.0
use crate::{ms, AttrId, Multisig};
use multiutil::{EncodedVarbytes, EncodingInfo, Varbytes};
use serde::ser::{self, SerializeStruct};

/// Serialize instance of [`crate::AttrId`]
impl ser::Serialize for AttrId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.as_str())
        } else {
            serializer.serialize_u8(self.code())
        }
    }
}

/// Serialize instance of [`crate::Multisig`]
impl ser::Serialize for Multisig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            let attributes: Vec<(String, EncodedVarbytes)> = self
                .attributes
                .iter()
                .map(|(id, attr)| {
                    (
                        id.to_string(),
                        Varbytes::encoded_new(self.encoding(), attr.clone()),
                    )
                })
                .collect();
            let message = Varbytes::encoded_new(self.encoding(), self.message.clone());

            let mut ss = serializer.serialize_struct(ms::SIGIL.as_str(), 3)?;
            ss.serialize_field("codec", &self.codec)?;
            ss.serialize_field("message", &message)?;
            ss.serialize_field("attributes", &attributes)?;
            ss.end()
        } else {
            let v: Vec<u8> = self.clone().into();
            serializer.serialize_bytes(v.as_slice())
        }
    }
}
