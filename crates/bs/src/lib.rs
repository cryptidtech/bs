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

/// bettersign operations
pub mod ops;
pub use ops::prelude::*;

/// convenient export
pub mod prelude {
    pub use super::*;
}

/// Opinionated configuation for the BetterSign library
pub mod config;
