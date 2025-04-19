// SPDX-License-Identifier: Apache-2.0

/// Filesystem backed data block
pub mod block;
pub use block::{Block, Builder as BlockBuilder};

/// Filesystem backed block storage
pub mod blocks;
pub use blocks::{Blocks, Builder as BlocksBuilder};

/// Filesystem errors
pub mod error;
pub use error::Error;

/// Abstract map to CIDs
pub mod cidmap;
pub use cidmap::CidMap;

/// Filesystem backed multikey to cid mapping
pub mod mkmap;
pub use mkmap::{Builder as MkMapBuilder, MkMap};

/// Generic content addressable storage
pub mod storage;
pub use storage::Storage;

/// Filesystem backed vlad to cid mapping
pub mod vladmap;
pub use vladmap::{Builder as VladMapBuilder, VladMap};

/*
/// Filesystem backed multikey_map storage
pub mod fsmultikey_map;
pub use fsmultikey_map::FsMultikeyMap;

*/

/// Simple way to import all public symbols
pub mod prelude {
    pub use super::*;
}
