//! Native specific code
//! The native platform impl of [blockstore::Blockstore]
use std::path::PathBuf;

//use bytes::Bytes;
//use tokio::io::AsyncReadExt as _;
//use wnfs_unixfs_file::builder::FileBuilder;
//use wnfs_unixfs_file::unixfs::UnixFsFile;

use blockstore::Blockstore;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// From core::Error
    #[error("Core error {0}")]
    P2p(#[from] bs_p2p::Error),

    /// From<libp2p::multiaddr::Error>
    #[error("Multiaddr error")]
    Multiaddr(#[from] libp2p::multiaddr::Error),

    /// From<libp2p::libp2p_identity::ParseError>
    #[error("Identity error")]
    Identity(#[from] libp2p::identity::ParseError),

    /// No data directory
    #[error("No data directory")]
    NoDataDir,

    /// Input output error
    #[error("IO error")]
    Io(#[from] std::io::Error),
    // /// from anyhow
    // #[error("error")]
    // Anyhow(#[from] anyhow::Error),
}

#[derive(Clone, Debug)]
pub struct NativeBlockstore {
    directory: PathBuf,
}

impl NativeBlockstore {
    /// Creates a new [NativeBlockstore]
    /// with the given directory path.
    pub async fn new(directory: PathBuf) -> Result<Self, Error> {
        // us tokio to create the directory if it does not exist
        if !directory.exists() {
            tokio::fs::create_dir_all(&directory).await?;
        }
        Ok(Self { directory })
    }
}

impl Blockstore for NativeBlockstore {
    async fn get<const S: usize>(
        &self,
        cid: &cid::CidGeneric<S>,
    ) -> blockstore::Result<Option<Vec<u8>>> {
        let path = self.directory.join(cid.to_string());

        if !path.exists() {
            return Ok(None);
        }

        let bytes =
            std::fs::read(&path).map_err(|e| blockstore::Error::StoredDataError(e.to_string()))?;

        Ok(Some(bytes))
    }

    async fn put_keyed<const S: usize>(
        &self,
        cid: &cid::CidGeneric<S>,
        data: &[u8],
    ) -> blockstore::Result<()> {
        let path = self.directory.join(cid.to_string());

        std::fs::write(&path, data)
            .map_err(|e| blockstore::Error::StoredDataError(e.to_string()))?;

        Ok(())
    }

    async fn remove<const S: usize>(&self, cid: &cid::CidGeneric<S>) -> blockstore::Result<()> {
        let path = self.directory.join(cid.to_string());

        std::fs::remove_file(&path)
            .map_err(|e| blockstore::Error::StoredDataError(e.to_string()))?;

        Ok(())
    }

    async fn close(self) -> blockstore::Result<()> {
        Ok(())
    }
}

///// A Chunker that takes bytes and chunks them
//pub async fn put_chunks<B: Blockstore + Clone>(
//    blockstore: B,
//    data: Vec<u8>,
//) -> Result<Cid, NativeError> {
//    let root_cid = FileBuilder::new()
//        .content_bytes(data.clone())
//        .fixed_chunker(256 * 1024)
//        .build()?
//        .store(&blockstore)
//        .await?;
//
//    Ok(root_cid)
//}

#[cfg(test)]
mod tests {
    use crate::platform::common::RawBlakeBlock;

    use super::*;
    use blockstore::{block::Block, Blockstore as _};
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_native_blockstore() {
        let tempdir = tempdir().unwrap().path().to_path_buf();
        let blockstore = NativeBlockstore::new(tempdir).await.unwrap();

        let data = b"hello world".to_vec();

        let block = RawBlakeBlock(data.clone());
        let cid = block.cid().unwrap();

        blockstore.put(block).await.unwrap();
        let retrieved_data = blockstore.get(&cid).await.unwrap();

        assert_eq!(data, retrieved_data.unwrap());
    }

    #[tokio::test]
    async fn test_put_large_bytes() {
        let tempdir = tempdir().unwrap().path().to_path_buf();
        let blockstore = NativeBlockstore::new(tempdir).await.unwrap();

        let len = 1 << 19; // 512KB, 2^19 bytes
        let data = vec![42; len];

        let block = RawBlakeBlock(data.clone());
        let root_cid = block.cid().unwrap();

        blockstore.put(block).await.unwrap();

        let retrieved_data = blockstore.get(&root_cid).await.unwrap();

        assert_eq!(data, retrieved_data.unwrap());
    }
}
