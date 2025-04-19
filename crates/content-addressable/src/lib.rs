// SPDX-License-Identifier: Apache-2.0

//! content-addressable
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

/// Abstract data block interface
pub mod block;
pub use block::Block;

/// Abstract block storage interface
pub mod blocks;
pub use blocks::Blocks;

/// Abstract mapping to CIDs
pub mod cids;
pub use cids::Cids;

/// Filesystem backed block storage
pub mod fs;
pub use fs::prelude::*;

/// Prelude convenience
pub mod prelude {
    pub use super::*;
    /// re-exports
    pub use multicid::{Cid, Vlad};
    pub use multicodec::Codec;
    pub use multikey::Multikey;
    pub use multiutil::BaseEncoded;
}
