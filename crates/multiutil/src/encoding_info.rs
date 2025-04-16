// SPDX-License-Idnetifier: Apache-2.0
use crate::prelude::Base;

/// This trait exposes the preferred encoding for this multicodec type
pub trait EncodingInfo {
    /// return the preferred encoding for this multicodec type
    fn preferred_encoding() -> Base;

    /// return the actual encoding for this multicodec type
    fn encoding(&self) -> Base;
}
