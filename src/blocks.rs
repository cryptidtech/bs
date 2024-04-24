// SPDX-License-Identifier: FSL-1.1
use crate::{initialize_data_dir, error::BlocksError, Error};
use multicid::{cid, Cid, EncodedCid};
use multicodec::Codec;
use multihash::mh;
use std::{convert::TryFrom, io::{Read, Write}, fs::File, path::PathBuf};

const ORG_DIRS: &'static [&'static str; 3] = &["tech", "cryptid", "bettersign"];

/// Blocks is a disk-based content addressable storage for data
#[derive(Clone, Debug)]
pub struct Blocks {
    /// root directory for blocks storage
    root: PathBuf,
}

impl wacc::Blocks for Blocks {
    type Error = Error;

    fn get(&self, key: &Cid) -> Result<Vec<u8>, Self::Error> {
        let cid: EncodedCid = key.clone().into();
        let mut pb = self.root.clone();
        pb.push(&cid.clone().to_string());
        if !pb.is_file() {
            Err(BlocksError::NoSuchBlock(cid.to_string()).into())
        } else {
            let mut f = File::open(&pb)?;
            let mut v = Vec::default();
            f.read_to_end(&mut v)?;
            Ok(v)
        }
    }

    fn put<F>(&mut self, data: &dyn AsRef<[u8]>, gen_cid: F) -> Result<Cid, Self::Error>
    where
        F: Fn(&dyn AsRef<[u8]>) -> Result<Cid, Self::Error>
    {
        // get the cid
        let cid: EncodedCid = gen_cid(data)?.into();
        let mut pb = self.root.clone();
        pb.push(&cid.clone().to_string());
        let mut f = File::create(&pb)?;
        f.write(data.as_ref())?;
        f.flush()?;
        Ok(cid.to_inner())
    }
}

impl Blocks {
    /// generates v1 CID's pointing at the data
    pub fn gen_cid(data: &dyn AsRef<[u8]>) -> Result<Cid, Error> {
        let cid = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::Identity)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3256, data.as_ref())?.try_build()?
            )
            .try_build()?;
        Ok(cid)
    }

    /// get a block from the storage
    pub fn get(&self, cid: &Cid) -> Result<Vec<u8>, Error> {
        Ok(<Self as wacc::Blocks>::get(self, cid)?)
    }

    /// put a block to the storage
    pub fn put(&mut self, data: &dyn AsRef<[u8]>) -> Result<Cid, Error> {
        Ok(<Self as wacc::Blocks>::put(self, data, |data| Self::gen_cid(data))?)
    }
}

impl TryFrom<Option<PathBuf>> for Blocks {
    type Error = Error;

    fn try_from(path: Option<PathBuf>) -> Result<Self, Self::Error> {
        //initialize the bettersign config file if needed
        let root = initialize_data_dir(path, ORG_DIRS)?;
        Ok(Self { root })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let mut b = Blocks::try_from(None).unwrap();
        let v = Vec::default();
        let c = b.put(&v).unwrap();
        let d = b.get(&c).unwrap();
        assert_eq!(v, d);
    }
}
