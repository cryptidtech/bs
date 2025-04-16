// SPDX-License-Identifier: FSL-1.1
use crate::Key;
use multiutil::Varbytes;
use serde::{
    de::Error,
    Deserialize, Deserializer,
};

/// Deserialize instance of [`crate::Key`]
impl<'de> Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s: &str = Deserialize::deserialize(deserializer)?;
            Ok(Key::try_from(s).map_err(Error::custom)?)
        } else {
            let k: Varbytes = Deserialize::deserialize(deserializer)?;
            Ok(Key::try_from(k.to_inner().as_slice()).map_err(Error::custom)?)
        }
    }
}
