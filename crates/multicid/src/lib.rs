// SPDX-License-Idnetifier: Apache-2.0

//! multicid
#![warn(missing_docs)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]

/// Errors produced by this library
pub mod error;
pub use error::Error;

/// Cid legacy content identifier types
pub mod cid;
pub use cid::{Cid, EncodedCid};

/// Vlad content identifier types
pub mod vlad;
pub use vlad::{EncodedVlad, Vlad};

/// Serde serialization for Multihash
#[cfg(feature = "serde")]
pub mod serde;

/// ...and in the darkness bind them
pub mod prelude {
    pub use super::*;
    /// re-exports
    pub use multibase::Base;
    pub use multicodec::Codec;
    pub use multiutil::BaseEncoded;
}
