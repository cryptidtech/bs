// SPDX-License-Identifier: Apache-2.0
use async_trait::async_trait;

/// Abstract block that abstracts away the Cid calculation
#[async_trait]
pub trait Block<'a, K>: Send + Sync {
    /// Return a reference to the data
    async fn data(&'a self) -> &'a [u8];

    /// Get the name of the block
    async fn key(&self) -> K;
}
