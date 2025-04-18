// SPDX-License-Identifier: FSL-1.1
use crate::Error;
use provenance_log::{script, Key, Script};
use std::{
    convert::TryFrom,
    path::{Path, PathBuf},
};

/// the provenance log Script loader/builder
#[derive(Clone, Debug, Default)]
pub struct Loader {
    /// the path to the script file
    pub path: PathBuf,

    /// the key-path for the script
    pub key_path: Option<String>,
}

impl Loader {
    /// initialize the loader with the path
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            ..Default::default()
        }
    }

    /// add in the key-path for the script
    pub fn with_key_path<S: AsRef<str>>(mut self, key_path: &S) -> Self {
        self.key_path = Some(key_path.as_ref().to_string());
        self
    }

    /// try to construct a proveannce log Script
    pub fn try_build(self) -> Result<Script, Error> {
        let key_path = match self.key_path {
            Some(k) => Key::try_from(k)?,
            None => Key::default(), // defaults to "/"
        };

        Ok(script::Builder::from_code_file(&self.path)
            .with_path(&key_path)
            .try_build()?)
    }
}
