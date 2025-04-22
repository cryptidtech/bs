// SPDX-License-Identifier: Apache-2.0
use crate::{Block as TBlock, Error};
use async_trait::async_trait;
use multibase::Base;
use multicid::{cid, Cid, EncodedCid};
use multicodec::Codec;
use multihash::mh;
use multiutil::{BaseEncoder, DetectedEncoder, EncodingInfo};
use std::marker::Unpin;
use tokio::io::{AsyncRead, AsyncReadExt};

/// The hash function we used when hashing blocks
pub const BLOCK_HASH: Codec = Codec::Blake2B256;

/// Filesystem stored block
#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    /// The block cid
    pub key: EncodedCid,
    /// The block data
    pub data: Vec<u8>,
}

#[async_trait]
impl<'a> TBlock<'a, EncodedCid> for Block {
    /// Return a reference to the data
    async fn data(&'a self) -> &'a [u8] {
        &self.data
    }

    /// Get the name of the block
    async fn key(&self) -> EncodedCid {
        self.key.clone()
    }
}

/// Builder for creating blocks from readers
#[derive(Clone, Debug)]
pub struct Builder<R: AsyncRead> {
    /// The base encoding
    base: Option<Base>,
    // The block cid
    cid: Option<Cid>,
    // The reader for the block data
    reader: R,
}

impl<R: AsyncRead + Unpin> Builder<R> {
    /// Create a new block builder
    pub fn new(reader: R) -> Self {
        Self {
            base: None,
            cid: None,
            reader,
        }
    }

    /// Set the base encoding
    pub fn base(mut self, base: Base) -> Self {
        self.base = Some(base);
        self
    }

    /// Set the cid
    pub fn cid(mut self, cid: Cid) -> Self {
        self.cid = Some(cid);
        self
    }

    /// Build the block
    pub async fn try_build(mut self) -> Result<Block, Error> {
        // get the base encoding
        let base = self.base.unwrap_or(DetectedEncoder::preferred_encoding(
            Cid::preferred_encoding(),
        ));

        // read the data from the reader
        let mut data = Vec::new();
        self.reader.read_to_end(&mut data).await?;

        // calculate the cid from the data if not provided
        let cid = match self.cid {
            Some(cid) => cid,
            None => cid::Builder::new(Codec::Cidv1)
                .with_target_codec(Codec::DagCbor)
                .with_hash(&mh::Builder::new_from_bytes(BLOCK_HASH, &data)?.try_build()?)
                .try_build()?,
        };

        // encode the cid into the key
        let key = EncodedCid::new(base, cid);

        Ok(Block { key, data })
    }
}
