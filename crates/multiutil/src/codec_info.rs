// SPDX-License-Idnetifier: Apache-2.0
use crate::prelude::Codec;

/// This trait exposes the codec information for multicoded types
pub trait CodecInfo {
    /// return the preferred codec associated with this object
    fn preferred_codec() -> Codec;

    /// return the actual codec associated with this object
    fn codec(&self) -> Codec;
}
