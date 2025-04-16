// SPDX-License-Identifier: FSL-1.1
use crate::{
    log::{Entries, SIGIL},
    Entry, Log, Script,
};
use core::fmt;
use multicid::{Cid, Vlad};
use serde::{
    de::{Error, MapAccess, Visitor},
    Deserialize, Deserializer,
};

/// Deserialize instance of [`crate::Log`]
impl<'de> Deserialize<'de> for Log {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] =
            &["version", "vlad", "first_lock", "foot", "head", "entries"];

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Version,
            Vlad,
            FirstLock,
            Foot,
            Head,
            Entries,
        }

        struct LogVisitor;

        impl<'de> Visitor<'de> for LogVisitor {
            type Value = Log;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "struct Log")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut version = None;
                let mut vlad = None;
                let mut first_lock = None;
                let mut foot = None;
                let mut head = None;
                let mut entries = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Version => {
                            if version.is_some() {
                                return Err(Error::duplicate_field("version"));
                            }
                            let v: u64 = map.next_value()?;
                            version = Some(v);
                        }
                        Field::Vlad => {
                            if vlad.is_some() {
                                return Err(Error::duplicate_field("vlad"));
                            }
                            let v: Vlad = map.next_value()?;
                            vlad = Some(v);
                        }
                        Field::FirstLock => {
                            if first_lock.is_some() {
                                return Err(Error::duplicate_field("first_lock"));
                            }
                            let s: Script = map.next_value()?;
                            first_lock = Some(s);
                        }
                        Field::Foot => {
                            if foot.is_some() {
                                return Err(Error::duplicate_field("foot"));
                            }
                            let c: Cid = map.next_value()?;
                            foot = Some(c);
                        }
                        Field::Head => {
                            if head.is_some() {
                                return Err(Error::duplicate_field("head"));
                            }
                            let c: Cid = map.next_value()?;
                            head = Some(c);
                        }
                        Field::Entries => {
                            if entries.is_some() {
                                return Err(Error::duplicate_field("entries"));
                            }
                            let ent: Vec<(Cid, Entry)> = map.next_value()?;
                            let mut e = Entries::new();
                            ent.iter()
                                .try_for_each(|(cid, entry)| -> Result<(), V::Error> {
                                    if e.insert(cid.clone(), entry.clone()).is_some() {
                                        return Err(Error::duplicate_field("duplicate entry cid"));
                                    }
                                    Ok(())
                                })?;
                            entries = Some(e);
                        }
                    }
                }
                let version = version.ok_or_else(|| Error::missing_field("version"))?;
                let vlad = vlad.ok_or_else(|| Error::missing_field("vlad"))?;
                let first_lock = first_lock.ok_or_else(|| Error::missing_field("first_lock"))?;
                let foot = foot.ok_or_else(|| Error::missing_field("foot"))?;
                let head = head.ok_or_else(|| Error::missing_field("head"))?;
                let entries = entries.ok_or_else(|| Error::missing_field("entries"))?;
                Ok(Self::Value {
                    version,
                    vlad,
                    first_lock,
                    foot,
                    head,
                    entries,
                })
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_struct(SIGIL.as_str(), FIELDS, LogVisitor)
        } else {
            let b: &'de [u8] = Deserialize::deserialize(deserializer)?;
            Ok(Self::try_from(b).map_err(|e| Error::custom(e.to_string()))?)
        }
    }
}
