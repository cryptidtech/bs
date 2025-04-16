// SPDX-License-Idnetifier: Apache-2.0
use crate::{
    error::BaseEncodedError, prelude::Base, BaseEncoder, EncodingInfo, Error, MultibaseEncoder,
};
use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops,
};

/// Smart pointer for multibase encoded data. This supports encoding to and
/// decoding from multibase encoding strings using [`TryFrom<&str>`] and
/// ['to_string()']
#[derive(Clone)]
pub struct BaseEncoded<T, Enc = MultibaseEncoder>
where
    T: EncodingInfo + ?Sized,
    Enc: BaseEncoder,
{
    pub(crate) enc: PhantomData<Enc>,
    pub(crate) base: Base,
    pub(crate) t: T,
}

impl<T, Enc> BaseEncoded<T, Enc>
where
    T: EncodingInfo,
    Enc: BaseEncoder,
{
    /// Construct a new BaseEncoded instance with the given base
    pub fn new(base: Base, t: T) -> Self {
        Self {
            base,
            t,
            enc: PhantomData,
        }
    }

    /// Convert to the inner T type, consuming self
    pub fn to_inner(self) -> T {
        self.t
    }
}

impl<T, Enc> EncodingInfo for BaseEncoded<T, Enc>
where
    T: EncodingInfo,
    Enc: BaseEncoder,
{
    /// Return the encoding hint for the contained type
    fn preferred_encoding() -> Base {
        // give the BaseEncoder a chance to overrule the inner type's preferred encoding
        Enc::preferred_encoding(T::preferred_encoding())
    }

    /// Return the encoding used to encode the contained object
    fn encoding(&self) -> Base {
        self.base
    }
}

impl<T, Enc> From<T> for BaseEncoded<T, Enc>
where
    T: EncodingInfo,
    Enc: BaseEncoder,
{
    fn from(t: T) -> Self {
        // give the BaseEncoder a chance to overrule the inner type's preferred encoding
        Self::new(Enc::preferred_encoding(T::preferred_encoding()), t)
    }
}

impl<T, Enc> TryFrom<&str> for BaseEncoded<T, Enc>
where
    T: EncodingInfo + for<'a> TryFrom<&'a [u8]>,
    Enc: BaseEncoder,
{
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match Enc::from_base_encoded(s) {
            Ok(decodings) => {
                for (base, v) in decodings {
                    if let Ok(t) = T::try_from(v.as_slice()) {
                        return Ok(Self {
                            base,
                            t,
                            enc: PhantomData,
                        })
                    }
                }
                Err(BaseEncodedError::ValueFailed.into())
            }
            Err(e) => Err(e),
        }
    }
}

impl<T, Enc> PartialEq<BaseEncoded<T, Enc>> for BaseEncoded<T, Enc>
where
    T: EncodingInfo + PartialEq<T> + ?Sized,
    Enc: BaseEncoder,
{
    fn eq(&self, other: &BaseEncoded<T, Enc>) -> bool {
        self.base == other.base && self.t == other.t
    }
}

impl<T, Enc> PartialOrd<BaseEncoded<T, Enc>> for BaseEncoded<T, Enc>
where
    T: EncodingInfo + PartialEq<T> + PartialOrd<T> + ?Sized,
    Enc: BaseEncoder,
{
    fn partial_cmp(&self, other: &BaseEncoded<T, Enc>) -> Option<Ordering> {
        self.t.partial_cmp(&other.t)
    }
}

impl<T, Enc> Eq for BaseEncoded<T, Enc>
where
    T: EncodingInfo + Eq + ?Sized,
    Enc: BaseEncoder,
{
}

impl<T, Enc> Ord for BaseEncoded<T, Enc>
where
    T: EncodingInfo + Eq + PartialOrd<T> + Ord + ?Sized,
    Enc: BaseEncoder,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.t.cmp(&other.t)
    }
}

impl<T, Enc> Hash for BaseEncoded<T, Enc>
where
    T: EncodingInfo + Clone + Into<Vec<u8>>,
    Enc: BaseEncoder,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        let s = self.to_string();
        s.hash(state);
    }
}

impl<T, Enc> ops::Deref for BaseEncoded<T, Enc>
where
    T: EncodingInfo,
    Enc: BaseEncoder,
{
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.t
    }
}

impl<T, Enc> ops::DerefMut for BaseEncoded<T, Enc>
where
    T: EncodingInfo,
    Enc: BaseEncoder,
{
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.t
    }
}

impl<T, Enc> fmt::Display for BaseEncoded<T, Enc>
where
    T: EncodingInfo + Clone + Into<Vec<u8>>,
    Enc: BaseEncoder,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            Enc::to_base_encoded(self.base, &self.t.clone().into())
        )
    }
}

impl<T, Enc> fmt::Debug for BaseEncoded<T, Enc>
where
    T: fmt::Debug + EncodingInfo + Clone + Into<Vec<u8>>,
    Enc: BaseEncoder,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} - {:?}", Enc::debug_string(self.base), self.t,)
    }
}
