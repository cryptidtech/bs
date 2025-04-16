// SPDX-License-Identifier: FSL-1.1
use crate::Key;
use multiutil::Varbytes;
use serde::ser;

/// Serialize instance of [`crate::Key`]
impl ser::Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.as_ref())
        } else {
            Varbytes(self.clone().into()).serialize(serializer)
        }
    }
}
