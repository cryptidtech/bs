// SPDX-License-Identifier: FSL-1.1
//! BetterSign
#![warn(missing_docs)]
//#![feature(trace_macros)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
//trace_macros!(true);

/// Error
pub mod error;
pub use error::Error;

/// The concrete type used for signatures in this crate.
pub type Signature = multisig::Multisig;

/// bettersign operations
pub mod ops;
pub use ops::prelude::*;

/// convenient export
pub mod prelude {
    pub use super::*;
    pub use multihash;
    pub use multikey;
}

/// Opinionated configuation for the BetterSign library
pub mod config;

/// Resolver extension for bettersign
pub mod resolver_ext;
