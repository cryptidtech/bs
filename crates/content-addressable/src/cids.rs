// SPDX-License-Identifier: Apache-2.0
use async_trait::async_trait;
use multicid::Cid;

/// Abstract mapping from an arbitrary key to a Cid
#[async_trait]
pub trait Cids<K> {
    /// The error type returned
    type Error;

    /// Try to confirm a key exists
    async fn exists(&self, key: &K) -> Result<bool, Self::Error>;

    /// Try to get a Cid from its key
    async fn get(&self, key: &K) -> Result<Cid, Self::Error>;

    /// Try to put a key and Cid into the map, returns the previous Cid value if it exists
    async fn put(&mut self, key: &K, cid: &Cid) -> Result<Option<Cid>, Self::Error>;

    /// Try to remove a key and Cid form the map
    async fn rm(&self, key: &K) -> Result<Cid, Self::Error>;
}
