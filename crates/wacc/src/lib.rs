// SPDX-License-Identifier: FSL-1.1
#![warn(missing_docs)]
#![allow(dead_code)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]

//! WACC

/// WACC API function implementations
pub(crate) mod api;

/// Errors produced by this library
pub mod error;
pub use error::Error;

/// Storage traits
pub mod storage;
pub use storage::{Pairs, Stack};

/// The virtual machine for executing WACC code
pub mod vm;
pub use vm::{Builder, Context, Instance, Value};

/// ...and in the darkness bind them
pub mod prelude {
    pub use super::*;
    // re-exports
    pub use wasmtime::StoreLimitsBuilder;
}
