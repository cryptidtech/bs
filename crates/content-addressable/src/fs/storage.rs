// SPDX-License-Identifier: Apache-2.0
use crate::{fs::Error as FsError, Error};
use multibase::Base;
use multiutil::{BaseEncoder, DetectedEncoder, EncodingInfo};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Display,
    marker::PhantomData,
    path::{Path, PathBuf},
};
use tokio::fs;
use tracing::info;

/// Filesystem block storage handle
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Storage<T>
where
    T: Clone + Display + EncodingInfo,
{
    /// The root directory
    pub root: PathBuf,
    /// Should folders be created lazily?
    pub lazy: bool,
    /// The base encoding for new CIDs
    #[serde(with = "serde_base")]
    pub base_encoding: Base,

    // phantoms
    _t: PhantomData<T>,
}

impl<T> EncodingInfo for Storage<T>
where
    T: Clone + Display + EncodingInfo,
{
    fn preferred_encoding() -> Base {
        DetectedEncoder::preferred_encoding(T::preferred_encoding())
    }

    fn encoding(&self) -> Base {
        self.base_encoding
    }
}

impl<T> Storage<T>
where
    T: Clone + Display + EncodingInfo,
{
    /// garbage collect the block storage to remove any lazy deleted files and empty subfolders
    pub async fn gc(&mut self) -> Result<(), Error> {
        for subfolder in &Self::subfolders(&self.root).await? {
            if !subfolder.try_exists()? {
                continue;
            }
            let mut dir = fs::read_dir(&subfolder).await?;
            while let Some(entry) = dir.next_entry().await? {
                let file = entry.path();
                if file.is_file() && entry.file_name().to_string_lossy().starts_with('.') {
                    fs::remove_file(&file).await?;
                    info!("GC'd file {}", file.display());
                }
            }
            if Self::count_dir(&subfolder).await? == 0 {
                fs::remove_dir(subfolder).await?;
                info!("GC'd subfolder {}", subfolder.display());
            }
        }
        Ok(())
    }

    /// get an iterator over the subfolders given the base encoding
    pub async fn subfolders<P: AsRef<Path>>(root: P) -> Result<Vec<PathBuf>, Error> {
        // create the root directory
        if !root.as_ref().try_exists()? {
            info!("creating root dir at {}", root.as_ref().display());
            fs::create_dir_all(&root).await?;
        }
        info!("root dir exists");

        // construct the directory structure using the alphabent of the base encoder
        Ok(T::preferred_encoding()
            .symbols(true)
            .chars()
            .map(|c| {
                let mut p = root.as_ref().to_path_buf();
                p.push(c.to_string());
                p
            })
            .collect())
    }

    /// count the number of files and dirs in a directory
    pub async fn count_dir<P: AsRef<Path>>(path: P) -> Result<usize, Error> {
        let mut count = 0;
        let mut dir = fs::read_dir(path.as_ref()).await?;
        while dir.next_entry().await?.is_some() {
            count += 1;
        }
        Ok(count)
    }

    pub(crate) async fn get_paths(&self, key: &T) -> Result<(T, PathBuf, PathBuf, PathBuf), Error> {
        let subfolder = self.get_subfolder(key).await?;
        let file = self.get_file(&subfolder, key).await?;
        let lazy_deleted_file = self.get_lazy_deleted_file(&subfolder, key).await?;
        Ok((key.clone(), subfolder, file, lazy_deleted_file))
    }

    async fn get_subfolder(&self, key: &T) -> Result<PathBuf, Error> {
        // get the middle char of the encoded CID
        let s = format!("{key}");
        let l = s.len();
        let c = s
            .chars()
            .nth_back(l >> 1)
            .ok_or(FsError::InvalidId(key.to_string()))?;

        // create a pathbuf to the subfolder
        let mut pb = self.root.clone();
        pb.push(c.to_string());

        Ok(pb)
    }

    async fn get_file<P: AsRef<Path>>(&self, subfolder: P, key: &T) -> Result<PathBuf, Error> {
        let mut pb = subfolder.as_ref().to_path_buf();
        pb.push(key.to_string());
        Ok(pb)
    }

    async fn get_lazy_deleted_file<P: AsRef<Path>>(
        &self,
        subfolder: P,
        key: &T,
    ) -> Result<PathBuf, Error> {
        let mut pb = subfolder.as_ref().to_path_buf();
        pb.push(format!(".{}", key));
        Ok(pb)
    }
}

pub(crate) mod serde_base {
    use multibase::Base;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S>(v: &Base, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_char(v.code())
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Base, D::Error>
    where
        D: Deserializer<'de>,
    {
        let c = char::deserialize(deserializer)?;
        let base = Base::from_code(c).map_err(serde::de::Error::custom)?;
        Ok(base)
    }
}

/// Builder for a Storage instance
#[derive(Clone, Debug, Default)]
pub struct Builder<T> {
    root: PathBuf,
    lazy: bool,
    base_encoding: Option<Base>,
    _t: PhantomData<T>,
}

impl<T> Builder<T>
where
    T: Clone + Display + EncodingInfo,
{
    /// create a new builder from the root path, this defaults to lazy
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        info!("Builder::new({})", root.as_ref().display());
        Builder {
            root: root.as_ref().to_path_buf(),
            lazy: true,
            base_encoding: None,
            _t: PhantomData,
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
    pub async fn try_build(&self) -> Result<Storage<T>, Error> {
        let lazy = self.lazy;
        let base_encoding = self
            .base_encoding
            .unwrap_or(Storage::<T>::preferred_encoding());

        // create the root directory
        let root = self.root.clone();
        if !root.try_exists()? {
            info!("Creating root folder at {}", root.display());
            fs::create_dir_all(&root).await?;
        }
        info!("Root dir exists");

        if !self.lazy {
            // construct the directory structure using the alphabent of the base encoder
            for subfolder in &Storage::<T>::subfolders(&root).await? {
                if !subfolder.try_exists()? {
                    info!("Creating subfolder {}", subfolder.display());
                    fs::create_dir_all(subfolder).await?;
                }
            }
        }

        Ok(Storage {
            root,
            lazy,
            base_encoding,
            _t: PhantomData,
        })
    }
}
