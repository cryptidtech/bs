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

/// BetterSign module for managing provenance logs
pub mod better_sign;
pub use better_sign::BetterSign;

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
// Re-export the concrete Signature type from config for convenience
pub use config::Signature;

/// Resolver extension for bettersign
pub mod resolver_ext;
