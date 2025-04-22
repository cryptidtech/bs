// SPDX-License-Identifier: Apache-2.0
use crate::{
    fs::{
        block,
        storage::{self, Storage},
        Error as FsError,
    },
    Block as TBlock, Blocks as TBlocks, Error,
};
use async_trait::async_trait;
use multibase::Base;
use multicid::EncodedCid;
use std::{
    io::Write,
    path::{Path, PathBuf},
};
use tokio::fs::{self, File};
use tracing::info;

/// The FsBlocks type uses CID's
pub type Blocks = Storage<EncodedCid>;

#[async_trait]
impl<'a, 'b> TBlocks<'a, 'b, EncodedCid> for Blocks {
    type Error = Error;

    async fn exists(&self, key: &EncodedCid) -> Result<bool, Self::Error> {
        // get the paths
        let (_, _, file, _) = self.get_paths(key).await?;
        Ok(file.try_exists()?)
    }

    async fn get(&self, key: &EncodedCid) -> Result<impl TBlock<'b, EncodedCid>, Self::Error> {
        // get the paths
        let (ecid, subfolder, file, _) = self.get_paths(key).await?;

        // check if it exists and is a dir...otherwise create the dir
        if subfolder.try_exists()? {
            if !subfolder.is_dir() {
                return Err(FsError::NotDir(subfolder).into());
            }
        } else {
            return Err(FsError::NoSuchData(ecid.to_string()).into());
        }

        // read the block from the filesystem
        info!("Getting block from: {}", file.display());
        let f = File::open(&file).await?;
        Ok(block::Builder::new(f).try_build().await?)
    }

    async fn put(
        &mut self,
        block: &'a impl TBlock<'a, EncodedCid>,
    ) -> Result<EncodedCid, Self::Error> {
        // get the paths
        let (key, subfolder, file, _) = self.get_paths(&block.key().await).await?;

        // check if it exists and is a dir...otherwise create the dir
        if subfolder.try_exists()? {
            if !subfolder.is_dir() {
                return Err(FsError::NotDir(subfolder).into());
            }
        } else {
            fs::create_dir_all(&subfolder).await?;
            info!("fsblocks: Created subfolder at: {}", subfolder.display());
        }

        // store the block in the filesystem
        info!("fsblocks: Storing block at: {}", file.display());

        // securely create a temporary file. its name begins with "." so that if something goes
        // wrong, the temporary file will be cleaned up by a future GC pass
        let mut temp = tempfile::Builder::new()
            .suffix(&format!(".{}", key))
            .tempfile_in(&subfolder)?;

        // write the contents to the file
        temp.write_all(block.data().await)?;

        // atomically rename/move it to the correct location
        temp.persist(&file)?;

        Ok(key)
    }

    async fn rm(&self, key: &EncodedCid) -> Result<impl TBlock<'b, EncodedCid>, Self::Error> {
        // first try to get the value
        let v = self.get(key).await?;

        // get the paths
        let (_, subfolder, file, lazy_deleted_file) = self.get_paths(key).await?;

        // remove the file if it exists
        if file.try_exists()? && file.is_file() {
            if self.lazy {
                // rename the file instead of remove it
                fs::rename(&file, &lazy_deleted_file).await?;
                info!(
                    "Lazy deleted block at: {} to {}",
                    file.display(),
                    lazy_deleted_file.display()
                );
            } else {
                // not lazy so delete it
                fs::remove_file(&file).await?;
                info!("Removed block at: {}", file.display());
            }
        }

        // remove the subfolder if it is emtpy and we're not lazy
        if subfolder.try_exists()?
            && subfolder.is_dir()
            && Self::count_dir(&subfolder).await? == 0
            && !self.lazy
        {
            fs::remove_dir(&subfolder).await?;
            info!("Removed subdir at: {}", subfolder.display());
        }

        Ok(v)
    }
}

/// Builder for a FsBlock instance
#[derive(Clone, Debug, Default)]
pub struct Builder {
    root: PathBuf,
    lazy: bool,
    base_encoding: Option<Base>,
}

impl Builder {
    /// create a new builder from the root path, this defaults to lazy
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        info!("fsblocks::Builder::new({})", root.as_ref().display());
        Builder {
            root: root.as_ref().to_path_buf(),
            lazy: true,
            base_encoding: None,
        }
    }

    /// set lazy to false
    pub fn not_lazy(mut self) -> Self {
        self.lazy = false;
        self
    }

    /// set the encoding codec to use for CIDs
    pub fn with_base_encoding(mut self, base: Base) -> Self {
        self.base_encoding = Some(base);
        self
    }

    /// build the instance
    pub async fn try_build(&self) -> Result<Blocks, Error> {
        let mut builder = storage::Builder::<EncodedCid>::new(&self.root);
        if let Some(base) = self.base_encoding {
            builder = builder.with_base_encoding(base);
        }
        if !self.lazy {
            builder = builder.not_lazy();
        }

        builder.try_build().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use multicid::Cid;
    use multiutil::EncodingInfo;
    use std::io::Cursor;
    use tokio::{io::BufReader, test};
    use tracing::{span, Level};

    #[test]
    async fn test_builder_lazy() {
        let _s = span!(Level::INFO, "test_builder_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsblocks1");

        let blocks = Builder::new(&pb).try_build().await.unwrap();
        assert_eq!(blocks.root, pb);
        assert!(blocks.lazy);
        assert_eq!(blocks.base_encoding, Cid::preferred_encoding());
        assert!(pb.try_exists().is_ok());
        assert!(pb.is_dir());

        assert!(fs::remove_dir_all(&pb).await.is_ok());
    }

    #[test]
    async fn test_builder_not_lazy() {
        let _s = span!(Level::INFO, "test_builder_not_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsblocks2");

        let blocks = Builder::new(&pb).not_lazy().try_build().await.unwrap();
        assert_eq!(blocks.root, pb);
        assert!(!blocks.lazy);
        assert_eq!(blocks.base_encoding, Cid::preferred_encoding());
        assert!(pb.try_exists().is_ok());
        assert!(pb.is_dir());

        let mut dir = fs::read_dir(&pb).await.unwrap();
        while let Some(d) = dir.next_entry().await.unwrap() {
            assert!(d.file_type().await.unwrap().is_dir());
        }

        assert!(fs::remove_dir_all(&pb).await.is_ok());
    }

    #[test]
    async fn test_put_lazy() {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsblocks3");

        let mut blocks = Builder::new(&pb).try_build().await.unwrap();

        let r = BufReader::new(Cursor::new(b"for great justice!"));
        let v1 = block::Builder::new(r).try_build().await.unwrap();
        let key1 = blocks.put(&v1).await.unwrap();
        let v2 = blocks.get(&key1).await.unwrap();
        assert_eq!(v1.key().await, v2.key().await);

        assert!(fs::remove_dir_all(&pb).await.is_ok());
    }

    #[test]
    async fn test_put_not_lazy() {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsblocks4");

        let mut blocks = Builder::new(&pb).not_lazy().try_build().await.unwrap();

        let r = BufReader::new(Cursor::new(b"for great justice!"));
        let v1 = block::Builder::new(r).try_build().await.unwrap();
        let key1 = blocks.put(&v1).await.unwrap();
        let v2 = blocks.get(&key1).await.unwrap();
        assert_eq!(v1.key().await, v2.key().await);

        assert!(fs::remove_dir_all(&pb).await.is_ok());
    }

    #[test]
    async fn test_rm_lazy() {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsblocks5");

        let mut blocks = Builder::new(&pb).try_build().await.unwrap();

        let r = BufReader::new(Cursor::new(b"for great justice!"));
        let v1 = block::Builder::new(r).try_build().await.unwrap();
        let key1 = blocks.put(&v1).await.unwrap();

        // get the paths to the subfolder and file created from the put
        let (_, _, file, lazy_deleted_file) = blocks.get_paths(&key1).await.unwrap();

        // lazy delete the block
        let v2 = blocks.rm(&key1).await.unwrap();
        assert_eq!(v1.key().await, v2.key().await);

        // this is lazy so the lazy deleted file should sill be there
        assert!(lazy_deleted_file.try_exists().unwrap());
        // and the file should not be there
        assert!(!file.try_exists().unwrap());

        assert!(fs::remove_dir_all(&pb).await.is_ok());
    }

    #[test]
    async fn test_rm_not_lazy() {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsblocks6");

        let mut blocks = Builder::new(&pb).not_lazy().try_build().await.unwrap();

        let r = BufReader::new(Cursor::new(b"for great justice!"));
        let v1 = block::Builder::new(r).try_build().await.unwrap();
        let key1 = blocks.put(&v1).await.unwrap();

        // get the paths to the subfolder and file created from the put
        let (_, subfolder, file, lazy_deleted_file) = blocks.get_paths(&key1).await.unwrap();

        // delete the block
        let v2 = blocks.rm(&key1).await.unwrap();
        assert_eq!(v1.key().await, v2.key().await);

        // this is not lazy so the lazy deleted file should not be there
        assert!(!lazy_deleted_file.try_exists().unwrap());
        // and the file should not be there either
        assert!(!file.try_exists().unwrap());
        // and since the subfolder is empty it should not be there either
        assert!(!subfolder.try_exists().unwrap());

        assert!(fs::remove_dir_all(&pb).await.is_ok());
    }

    #[test]
    async fn test_gc() {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsblocks7");

        let mut blocks = Builder::new(&pb).try_build().await.unwrap();

        let r1 = BufReader::new(Cursor::new(b"for great justice!"));
        let v1 = block::Builder::new(r1).try_build().await.unwrap();
        let key1 = blocks.put(&v1).await.unwrap();
        let r2 = BufReader::new(Cursor::new(b"move every zig!"));
        let v2 = block::Builder::new(r2).try_build().await.unwrap();
        let key2 = blocks.put(&v2).await.unwrap();

        let _ = blocks.rm(&key1).await.unwrap();
        let _ = blocks.rm(&key2).await.unwrap();

        // lazy delete, check that the file is gone, the lazy delete file and folder still exist
        let (_, subfolder1, file1, lazy_deleted_file1) = blocks.get_paths(&key1).await.unwrap();
        assert!(lazy_deleted_file1.try_exists().unwrap());
        assert!(!file1.try_exists().unwrap());
        assert!(subfolder1.try_exists().unwrap());

        // lazy delete, check that the file is gone, the lazy delete file and folder still exist
        let (_, subfolder2, file2, lazy_deleted_file2) = blocks.get_paths(&key2).await.unwrap();
        assert!(lazy_deleted_file2.try_exists().unwrap());
        assert!(!file2.try_exists().unwrap());
        assert!(subfolder2.try_exists().unwrap());

        // garbage collect
        blocks.gc().await.unwrap();

        // no files nor folders should exist
        assert!(!lazy_deleted_file1.try_exists().unwrap());
        assert!(!file1.try_exists().unwrap());
        assert!(!subfolder1.try_exists().unwrap());
        assert!(!lazy_deleted_file2.try_exists().unwrap());
        assert!(!file2.try_exists().unwrap());
        assert!(!subfolder2.try_exists().unwrap());

        assert!(fs::remove_dir_all(&pb).await.is_ok());
    }
}
