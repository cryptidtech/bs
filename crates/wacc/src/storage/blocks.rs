// SPDX-License-Identifier: FSL-1.1
use multicid::Cid;

/// Block storage trait for getting and putting content address data
pub trait Blocks {
    /// The error type returned in put
    type Error;

    /// Try to get a block from it's content address
    fn get(&self, cid: &Cid) -> Result<Vec<u8>, Self::Error>;

    /// Try to put a block and get back its content address
    fn put<F: Fn(&dyn AsRef<[u8]>) -> Result<Cid, Self::Error>>(
        &mut self, data: &dyn AsRef<[u8]>, gen_cid: F) -> Result<Cid, Self::Error>;
}
