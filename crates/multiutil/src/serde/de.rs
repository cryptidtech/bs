// SPDX-License-Idnetifier: Apache-2.0
use crate::{BaseEncoded, BaseEncoder, EncodingInfo, Varbytes, Varuint};
use core::{fmt, marker};
use multibase::Base;
use multitrait::prelude::TryDecodeFrom;
use serde::de;

/// Deserialize instance of [`crate::BaseEncoded`] from a byte slice
impl<'de, T, Enc> de::Deserialize<'de> for BaseEncoded<T, Enc>
where
    T: de::Deserialize<'de> + EncodingInfo + for<'a> TryFrom<&'a [u8]>,
    Enc: BaseEncoder,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        #[derive(Clone, Default)]
        struct BaseEncodedVisitor<T, Enc> {
            _enc: marker::PhantomData<Enc>,
            _t: marker::PhantomData<T>,
        }

        impl<'de, T, Enc> de::Visitor<'de> for BaseEncodedVisitor<T, Enc>
        where
            T: de::Deserialize<'de> + EncodingInfo + for<'a> TryFrom<&'a [u8]>,
            Enc: BaseEncoder,
        {
            type Value = BaseEncoded<T, Enc>;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "borrowed str, str, String, or tuple of (u8, T)")
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

            #[inline]
            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Self::Value::try_from(s).map_err(|e| de::Error::custom(e.to_string()))
            }

            // longest lifetime
            #[inline]
            fn visit_string<E>(self, s: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Self::Value::try_from(s.as_str()).map_err(|e| de::Error::custom(e.to_string()))
            }

            // binary
            #[inline]
            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: de::SeqAccess<'de>,
            {
                let base = match seq.next_element::<char>()? {
                    Some(b) => Base::from_code(b).map_err(|e| de::Error::custom(e.to_string()))?,
                    None => {
                        return Err(de::Error::custom("expected base encoding char".to_string()))
                    }
                };

                let t = match seq.next_element()? {
                    Some(t) => t,
                    None => return Err(de::Error::custom("expected inner type value".to_string())),
                };

                Ok(Self::Value {
                    enc: marker::PhantomData,
                    base,
                    t,
                })
            }
        }

        deserializer.deserialize_any(BaseEncodedVisitor {
            _enc: marker::PhantomData,
            _t: marker::PhantomData,
        })
    }
}

/// Deserialize instance of [`crate::Varuint`] from a byte slice
impl<'de, T> de::Deserialize<'de> for Varuint<T>
where
    T: for<'a> TryDecodeFrom<'a>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct VaruintVisitor<T>(marker::PhantomData<T>);

        impl<'de, T> de::Visitor<'de> for VaruintVisitor<T>
        where
            T: for<'a> TryDecodeFrom<'a>,
        {
            type Value = Varuint<T>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "varuint encoded numeric value")
            }

            // only binary

            // shortest lifetime
            #[inline]
            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let (t, _) = T::try_decode_from(v)
                    .map_err(|_| de::Error::custom("failed to deserialize varuint bytes"))?;
                Ok(Varuint(t))
            }

            #[inline]
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let (t, _) = T::try_decode_from(v)
                    .map_err(|_| de::Error::custom("failed to deserialize varuint bytes"))?;
                Ok(Varuint(t))
            }

            // longest lifetime
            #[inline]
            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let (t, _) = T::try_decode_from(v.as_slice())
                    .map_err(|_| de::Error::custom("failed to deserialize varuint bytes"))?;
                Ok(Varuint(t))
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
                let (t, _) = T::try_decode_from(v.as_slice())
                    .map_err(|_| de::Error::custom("failed to deserialize varuint bytes"))?;
                Ok(Varuint(t))
            }
        }

        deserializer.deserialize_bytes(VaruintVisitor::<T>(marker::PhantomData::<T>))
    }
}

/// Deserialize instance of [`crate::Varbytes`] from a byte slice
impl<'de> de::Deserialize<'de> for Varbytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct VarbytesVisitor;

        impl<'de> de::Visitor<'de> for VarbytesVisitor {
            type Value = Varbytes;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "varuint encoded len followed by bytes")
            }

            // only binary

            // shortest lifetime
            #[inline]
            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let (len, ptr) = usize::try_decode_from(v)
                    .map_err(|_| de::Error::custom("failed to deserialize varuint len"))?;
                let v = ptr[..len].to_vec();
                Ok(Varbytes(v))
            }

            #[inline]
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let (len, ptr) = usize::try_decode_from(v)
                    .map_err(|_| de::Error::custom("failed to deserialize varuint len"))?;
                let v = ptr[..len].to_vec();
                Ok(Varbytes(v))
            }

            // longest lifetime
            #[inline]
            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let (len, ptr) = usize::try_decode_from(v.as_slice())
                    .map_err(|_| de::Error::custom("failed to deserialize varuint len"))?;
                let v = ptr[..len].to_vec();
                Ok(Varbytes(v))
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
                let (len, ptr) = usize::try_decode_from(v.as_slice())
                    .map_err(|_| de::Error::custom("failed to deserialize varuint len"))?;
                let v = ptr[..len].to_vec();
                Ok(Varbytes(v))
            }
        }

        deserializer.deserialize_bytes(VarbytesVisitor)
    }
}
