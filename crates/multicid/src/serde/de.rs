// SPDX-License-Idnetifier: Apache-2.0
use crate::{vlad, Cid, Vlad};
use core::fmt;
use multicodec::Codec;
use multihash::Multihash;
use multikey::Nonce;
#[cfg(feature = "dag_cbor")]
use multitrait::TryDecodeFrom;
use serde::{
    de::{Error, MapAccess, Visitor},
    Deserialize, Deserializer,
};

/// Deserialize instance of [`crate::Cid`]
impl<'de> Deserialize<'de> for Cid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["version", "encoding", "hash"];

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Version,
            Encoding,
            Hash,
        }

        struct CidVisitor;

        impl<'de> Visitor<'de> for CidVisitor {
            type Value = Cid;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "struct Cid")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Cid, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut codec = None;
                let mut target_codec = None;
                let mut hash = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Version => {
                            if codec.is_some() {
                                return Err(Error::duplicate_field("version"));
                            }
                            let v: u64 = map.next_value()?;
                            codec = Some(
                                Codec::try_from(v)
                                    .map_err(|_| Error::custom("invalid cid version"))?,
                            );
                        }
                        Field::Encoding => {
                            if target_codec.is_some() {
                                return Err(Error::duplicate_field("encoding"));
                            }
                            let s: &str = map.next_value()?;
                            target_codec = Some(
                                Codec::try_from(s)
                                    .map_err(|_| Error::custom("invalid cid encoding"))?,
                            );
                        }
                        Field::Hash => {
                            if hash.is_some() {
                                return Err(Error::duplicate_field("hash"));
                            }
                            let mh: Multihash = map.next_value()?;
                            hash = Some(mh);
                        }
                    }
                }
                let codec = codec.ok_or_else(|| Error::missing_field("version"))?;
                let target_codec = target_codec.ok_or_else(|| Error::missing_field("encoding"))?;
                let hash = hash.ok_or_else(|| Error::missing_field("hash"))?;
                Ok(Self::Value {
                    codec,
                    target_codec,
                    hash,
                })
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_struct("cid", FIELDS, CidVisitor)
        } else {
            #[cfg(feature = "dag_cbor")]
            {
                let tagged: serde_cbor::tags::Tagged<&'de [u8]> =
                    Deserialize::deserialize(deserializer)?;
                if tagged.tag != Some(42_u64) {
                    return Err(Error::custom("improperly tagged DAG-CBOR CID"));
                }
                let (identity, ptr) = Codec::try_decode_from(tagged.value)
                    .map_err(|e| Error::custom(e.to_string()))?;
                if identity != Codec::Identity {
                    return Err(Error::custom(
                        "improperly encoded DAG-CBOR CID; missing leading Identity codec",
                    ));
                }
                let (cid, _) =
                    Self::try_decode_from(ptr).map_err(|e| Error::custom(e.to_string()))?;

                if cid.codec != Codec::Identity
                    && cid.codec != Codec::Cidv1
                    && cid.codec != Codec::Cidv2
                    && cid.codec != Codec::Cidv3
                {
                    return Err(Error::custom("deserialized sigil is not a Cid sigil"));
                }

                Ok(cid)
            }

            #[cfg(not(feature = "dag_cbor"))]
            {
                let b: &'de [u8] = Deserialize::deserialize(deserializer)?;
                Ok(Self::try_from(b).map_err(|e| Error::custom(e.to_string()))?)
            }
        }
    }
}

/// Deserialize instance of [`crate::Vlad`]
impl<'de> Deserialize<'de> for Vlad {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["nonce", "cid"];

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Nonce,
            Cid,
        }

        struct VladVisitor;

        impl<'de> Visitor<'de> for VladVisitor {
            type Value = Vlad;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "struct Vlad")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Vlad, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut nonce = None;
                let mut cid = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Nonce => {
                            if nonce.is_some() {
                                return Err(Error::duplicate_field("nonce"));
                            }
                            let n: Nonce = map.next_value()?;
                            nonce = Some(n);
                        }
                        Field::Cid => {
                            if cid.is_some() {
                                return Err(Error::duplicate_field("cid"));
                            }
                            let c: Cid = map.next_value()?;
                            cid = Some(c);
                        }
                    }
                }
                let nonce = nonce.ok_or_else(|| Error::missing_field("nonce"))?;
                let cid = cid.ok_or_else(|| Error::missing_field("cid"))?;
                Ok(Self::Value { nonce, cid })
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_struct(vlad::SIGIL.as_str(), FIELDS, VladVisitor)
        } else {
            let b: &'de [u8] = Deserialize::deserialize(deserializer)?;
            Ok(Self::try_from(b).map_err(|e| Error::custom(e.to_string()))?)
        }
    }
}
