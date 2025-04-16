// SPDX-License-Idnetifier: Apache-2.0
//! multihash
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

/// Multihash type and functions
pub mod mh;
pub use mh::{HASH_CODECS, SAFE_HASH_CODECS, Builder, EncodedMultihash, Multihash};

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
