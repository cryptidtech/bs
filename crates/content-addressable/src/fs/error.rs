// SPDX-License-Idnetifier: Apache-2.0

/// Error from FsStorage
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// unsupported base encoding for Cids
    #[error("Unsupported base encoding {0:?}")]
    UnsupportedBaseEncoding(multibase::Base),
    /// the path exists but it isn't a dir
    #[error("Path is not a directory {0}")]
    NotDir(std::path::PathBuf),
    /// the id for the data is invalid
    #[error("Invalid id {0}")]
    InvalidId(String),
    /// the id doesn't refer to data
    #[error("No such data {0}")]
    NoSuchData(String),
}
