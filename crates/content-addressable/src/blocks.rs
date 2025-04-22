// SPDX-License-Identifier: Apache-2.0
use crate::Block;
use async_trait::async_trait;

/// Abstract block storage trait for getting and putting content addressed data
#[async_trait]
pub trait Blocks<'a, 'b, K> {
    /// The error type returned
    type Error;

    /// Try to confirm a block exists
    async fn exists(&self, key: &K) -> Result<bool, Self::Error>;

    /// Try to get a block from its content address
    async fn get(&self, key: &K) -> Result<impl Block<'b, K>, Self::Error>;

    /// Try to put a block into storage
    async fn put(&mut self, block: &'a impl Block<'a, K>) -> Result<K, Self::Error>;

    /// Try to remove a block from storage
    async fn rm(&self, key: &K) -> Result<impl Block<'b, K>, Self::Error>;
}
