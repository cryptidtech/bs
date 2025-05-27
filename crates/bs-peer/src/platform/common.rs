//! Common types and constants used across the platform.

use blockstore::block::{Block, CidError};
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

const RAW_CODEC: u64 = 0x55;

/// A block that is just raw bytes encoded into a block
/// using the `RAW_CODEC` and `Blake3_256` hash function.
pub struct RawBlakeBlock(pub Vec<u8>);

impl Block<64> for RawBlakeBlock {
    fn cid(&self) -> Result<Cid, CidError> {
        let hash = Code::Blake3_256.digest(&self.0);
        Ok(Cid::new_v1(RAW_CODEC, hash))
    }

    fn data(&self) -> &[u8] {
        self.0.as_ref()
    }
}
