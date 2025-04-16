// SPDX-License-Identifier: FSL-1.1
use crate::{entry::SIGIL, Entry, Op, Script};
use core::fmt;
use multicid::{Cid, Vlad};
use multiutil::Varbytes;
use serde::{
    de::{Error, MapAccess, Visitor},
    Deserialize, Deserializer,
};

/// Deserialize instance of [`crate::Entry`]
impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "version", "vlad", "prev", "lipmaa", "seqno", "ops", "locks", "unlock", "proof",
        ];

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Version,
            Vlad,
            Prev,
            Lipmaa,
            Seqno,
            Ops,
            Locks,
            Unlock,
            Proof,
        }

        struct EntryVisitor;

        impl<'de> Visitor<'de> for EntryVisitor {
            type Value = Entry;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "struct Entry")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut version = None;
                let mut vlad = None;
                let mut prev = None;
                let mut lipmaa = None;
                let mut seqno = None;
                let mut ops = None;
                let mut locks = None;
                let mut unlock = None;
                let mut proof = None;
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
                        Field::Prev => {
                            if prev.is_some() {
                                return Err(Error::duplicate_field("prev"));
                            }
                            let c: Cid = map.next_value()?;
                            prev = Some(c);
                        }
                        Field::Lipmaa => {
                            if lipmaa.is_some() {
                                return Err(Error::duplicate_field("lipmaa"));
                            }
                            let c: Cid = map.next_value()?;
                            lipmaa = Some(c);
                        }
                        Field::Seqno => {
                            if seqno.is_some() {
                                return Err(Error::duplicate_field("seqno"));
                            }
                            let v: u64 = map.next_value()?;
                            seqno = Some(v);
                        }
                        Field::Ops => {
                            if ops.is_some() {
                                return Err(Error::duplicate_field("ops"));
                            }
                            let o: Vec<Op> = map.next_value()?;
                            ops = Some(o);
                        }
                        Field::Locks => {
                            if locks.is_some() {
                                return Err(Error::duplicate_field("locks"));
                            }
                            let l: Vec<Script> = map.next_value()?;
                            locks = Some(l)
                        }
                        Field::Unlock => {
                            if unlock.is_some() {
                                return Err(Error::duplicate_field("unlock"));
                            }
                            let s: Script = map.next_value()?;
                            unlock = Some(s);
                        }
                        Field::Proof => {
                            if proof.is_some() {
                                return Err(Error::duplicate_field("proof"));
                            }
                            let v: Varbytes = map.next_value()?;
                            proof = Some(v.to_inner());
                        }
                    }
                }
                let version = version.ok_or_else(|| Error::missing_field("version"))?;
                let vlad = vlad.ok_or_else(|| Error::missing_field("vlad"))?;
                let prev = prev.ok_or_else(|| Error::missing_field("prev"))?;
                let lipmaa = lipmaa.ok_or_else(|| Error::missing_field("lipmaa"))?;
                let seqno = seqno.ok_or_else(|| Error::missing_field("seqno"))?;
                let ops = ops.ok_or_else(|| Error::missing_field("ops"))?;
                let locks = locks.ok_or_else(|| Error::missing_field("locks"))?;
                let unlock = unlock.ok_or_else(|| Error::missing_field("unlock"))?;
                let proof = proof.ok_or_else(|| Error::missing_field("proof"))?;
                Ok(Self::Value {
                    version,
                    vlad,
                    prev,
                    lipmaa,
                    seqno,
                    ops,
                    locks,
                    unlock,
                    proof,
                })
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_struct(SIGIL.as_str(), FIELDS, EntryVisitor)
        } else {
            let b: &'de [u8] = Deserialize::deserialize(deserializer)?;
            Ok(Self::try_from(b).map_err(|e| Error::custom(e.to_string()))?)
        }
    }
}
