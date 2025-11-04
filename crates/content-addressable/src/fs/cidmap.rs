// SPDX-License-Identifier: Apache-2.0
use crate::{
    fs::{
        storage::{self, Storage},
        Error as FsError,
    },
    Cids, Error,
};
use async_trait::async_trait;
use multibase::Base;
use multicid::Cid;
use multiutil::EncodingInfo;
use serde::{Deserialize, Serialize};
use std::{
    fmt::Display,
    io::Write,
    marker::PhantomData,
    path::{Path, PathBuf},
};
use tokio::{
    fs::{self, File},
    io::AsyncReadExt,
};
use tracing::debug;

/// The Generic CidMap
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CidMap<K: Clone + Display + EncodingInfo + Sync + Send>(pub(crate) Storage<K>);

#[async_trait]
impl<K> Cids<K> for CidMap<K>
where
    K: Clone + Display + EncodingInfo + Sync + Send,
{
    type Error = Error;

    async fn exists(&self, key: &K) -> Result<bool, Self::Error> {
        // get the paths
        let (_, _, file, _) = self.0.get_paths(key).await?;
        Ok(file.try_exists()?)
    }

    async fn get(&self, key: &K) -> Result<Cid, Self::Error> {
        // get the paths
        let (eid, subfolder, file, _) = self.0.get_paths(key).await?;

        // check if it exists and is a dir...otherwise create the dir
        if subfolder.try_exists()? {
            if !subfolder.is_dir() {
                return Err(FsError::NotDir(subfolder).into());
            }
        } else {
            return Err(FsError::NoSuchData(eid.to_string()).into());
        }

        // store the mapping in the filesystem
        debug!("Getting Cid from: {}", file.display());
        let mut f = File::open(&file).await?;
        let mut data = Vec::default();
        f.read_to_end(&mut data).await?;

        // reconstruct the Cid from the data
        let cid = Cid::try_from(data.as_slice())?;
        Ok(cid)
    }

    async fn put(&mut self, key: &K, cid: &Cid) -> Result<Option<Cid>, Self::Error> {
        // get the paths
        let (eid, subfolder, file, _) = self.0.get_paths(key).await?;

        // check if it exists and is a dir...otherwise create the dir
        if subfolder.try_exists()? {
            if !subfolder.is_dir() {
                return Err(FsError::NotDir(subfolder).into());
            }
        } else {
            fs::create_dir_all(&subfolder).await?;

            if !subfolder.try_exists()? || !subfolder.is_dir() {
                return Err(FsError::CreateDirFailed(subfolder.clone()).into());
            }
            debug!("Created subfolder at: {}", subfolder.display());
        }

        // store the Cid in the filesystem
        debug!("Storing Cid at: {}", file.display());

        // try to get the existing cid value
        let prev_cid = self.get(key).await.ok();

        // securely create a temporary file. its name begins with "." so that if something goes
        // wrong, the temporary file will be cleaned up by a future GC pass
        // Create a temporary file with better error handling
        let temp_result = tempfile::Builder::new()
            .suffix(&format!(".{}", eid))
            .tempfile_in(&subfolder);

        let mut temp = match temp_result {
            Ok(temp) => temp,
            Err(e) => {
                // If tempfile creation fails, verify directory exists
                if !subfolder.try_exists()? {
                    // Try to create directory again
                    fs::create_dir_all(&subfolder).await?;

                    // Try again with temporary file
                    tempfile::Builder::new()
                        .suffix(&format!(".{}", eid))
                        .tempfile_in(&subfolder)?
                } else {
                    return Err(Error::from(e));
                }
            }
        };

        // write the contents to the file
        let data: Vec<u8> = cid.clone().into();
        temp.write_all(data.as_ref())?;

        // atomically rename/move it to the correct location
        match temp.persist(&file) {
            Ok(_) => {
                debug!("Successfully persisted file at: {}", file.display());
                Ok(prev_cid)
            }
            Err(e) => {
                debug!("Failed to persist file: {:?}", e);
                Err(Error::from(e))
            }
        }
    }

    async fn rm(&self, key: &K) -> Result<Cid, Self::Error> {
        // first try to get the value
        let v = self.get(key).await?;

        // get the paths
        let (_, subfolder, file, lazy_deleted_file) = self.0.get_paths(key).await?;

        // remove the file if it exists
        if file.try_exists()? && file.is_file() {
            if self.0.lazy {
                // rename the file instead of remove it
                fs::rename(&file, &lazy_deleted_file).await?;
                debug!(
                    "Lazy deleted mapping at: {} to {}",
                    file.display(),
                    lazy_deleted_file.display()
                );
            } else {
                // not lazy so delete it
                fs::remove_file(&file).await?;
                debug!("Removed mapping at: {}", file.display());
            }
        }

        // remove the subfolder if it is emtpy and we're not lazy
        if subfolder.try_exists()?
            && subfolder.is_dir()
            && Storage::<K>::count_dir(&subfolder).await? == 0
            && !self.0.lazy
        {
            fs::remove_dir(&subfolder).await?;
            debug!("Removed subdir at: {}", subfolder.display());
        }

        Ok(v)
    }
}

/// Builder for a FsMultikeyMap instance
#[derive(Clone, Debug, Default)]
pub struct Builder<K> {
    root: PathBuf,
    lazy: bool,
    base_encoding: Option<Base>,
    _k: PhantomData<K>,
}

impl<K> Builder<K>
where
    K: Clone + Display + EncodingInfo + Sync + Send,
{
    /// create a new builder from the root path, this defaults to lazy
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        debug!("fsmultikey_map::Builder::new({})", root.as_ref().display());
        Builder {
            root: root.as_ref().to_path_buf(),
            lazy: true,
            base_encoding: None,
            _k: PhantomData,
        }
    }

    /// set lazy to false
    pub fn not_lazy(mut self) -> Self {
        self.lazy = false;
        self
    }

    /// set the encoding codec to use for mks
    pub fn with_base_encoding(mut self, base: Base) -> Self {
        self.base_encoding = Some(base);
        self
    }

    /// build the instance
    pub async fn try_build(&self) -> Result<CidMap<K>, Error> {
        let mut builder = storage::Builder::<K>::new(&self.root);
        if let Some(base) = self.base_encoding {
            builder = builder.with_base_encoding(base);
        }
        if !self.lazy {
            builder = builder.not_lazy();
        }

        Ok(CidMap(builder.try_build().await?))
    }
}
