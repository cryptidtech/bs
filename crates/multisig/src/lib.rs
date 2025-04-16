// SPDX-License-Idnetifier: Apache-2.0
//! multisig
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

/// Attribute Ids
pub mod attrid;
pub use attrid::AttrId;

/// Multisig implementation
pub mod ms;
pub use ms::{SIG_CODECS, SIG_SHARE_CODECS, Builder, EncodedMultisig, Multisig};

/// Views on the multisig
pub mod views;
pub use views::{AttrView, ConvView, DataView, ThresholdAttrView, ThresholdView, Views};

/// Serde serialization
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
