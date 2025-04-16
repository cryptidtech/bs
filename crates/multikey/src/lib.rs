// SPDX-License-Idnetifier: Apache-2.0
//! Multikey Crate
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

/// Multikey attribute IDs
pub mod attrid;
pub use attrid::AttrId;

/// Cipher function builder
pub mod cipher;

/// Key derivation function builder
pub mod kdf;

/// Key views
pub mod views;
pub use views::{
    AttrView, CipherAttrView, CipherView, ConvView, DataView, FingerprintView, KdfAttrView,
    KdfView, SignView, ThresholdAttrView, ThresholdView, VerifyView, Views,
};

/// Multikey type and functions
pub mod mk;
pub use mk::{Builder, EncodedMultikey, Multikey, KEY_CODECS, KEY_SHARE_CODECS};

/// Nonce type
pub mod nonce;
pub use nonce::{EncodedNonce, Nonce};

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
