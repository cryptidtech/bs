// SPDX-License-Identifier: FSL-1.1
use crate::{initialize_local_file, Backend, Error, Keychain, KeychainConfig, LocalFile, SshAgent};
use log::debug;
use multihash::EncodedMultihash;
use multikey::Multikey;
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    convert::TryFrom,
    fs::{self, File},
    io::Write,
    path::PathBuf,
    rc::Rc,
};

const CONFIG_FILE: &'static str = "config.toml";
const ORG_DIRS: &'static [&'static str; 3] = &["tech", "cryptid", "bettersign"];

/// The configuration for the bs crate loaded from disk using the correct OS
/// path to look for a file
#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to the confid file
    #[serde(skip)]
    path: PathBuf,

    /// Cached keychain handle
    #[serde(skip)]
    handle: Option<Rc<RefCell<dyn Keychain>>>,

    /// Keychain config
    keychain: KeychainConfig,
}

impl Config {
    /// construct a Config from the serialized config file, creating a new one
    /// if one doesn't already exist
    pub fn from_path(
        path: Option<PathBuf>,
        keyfile: Option<PathBuf>,
        sshagent: bool,
        sshagentenv: String,
    ) -> Result<Self, Error> {
        //initialize the bettersign config file if needed
        let config_path = initialize_local_file(path, ORG_DIRS, CONFIG_FILE, |pb| {
            debug!("creating default config: {}", pb.display());
            let keychain = KeychainConfig::new(keyfile, sshagent, sshagentenv);
            let config = Config {
                path: pb.clone(),
                handle: None,
                keychain,
            };
            let toml = toml::to_string(&config)?;
            let mut f = File::create(&pb)?;
            f.write_all(toml.as_bytes())?;
            Ok(())
        })?;

        let toml = fs::read_to_string(&config_path)?;
        let mut config: Self = toml::from_str(&toml)?;
        config.path = config_path.clone();
        Ok(config)
    }

    /// Loads the actual keychain
    pub fn keychain(&mut self) -> Result<Rc<RefCell<dyn Keychain>>, Error> {
        if self.handle.is_none() {
            self.handle = Some(match self.keychain.storage {
                Backend::LocalFile => {
                    let keyfile = LocalFile::try_from(self.keychain.keyfile.clone())?;
                    Rc::new(RefCell::new(keyfile))
                }
                Backend::SshAgent => {
                    let sshagent = SshAgent::try_from(self.keychain.sshagent.clone())?;
                    Rc::new(RefCell::new(sshagent))
                }
            });
        }

        match &self.handle {
            Some(h) => Ok(h.clone()),
            None => Err(Error::NoKeychain),
        }
    }

    /// set default key
    pub fn set_default_key(&mut self, hash: Option<String>) -> Result<(), Error> {
        // see if there is a matching key and set it as default
        if let Some(hash) = hash {
            let fingerprint = EncodedMultihash::try_from(hash.as_str())?;
            if self.keychain()?.borrow().get(&fingerprint).is_ok() {
                debug!("found key: {}", fingerprint.to_string());
                self.keychain.default_key = Some(fingerprint);
            }
        } else {
            self.keychain.default_key = None;
        }
        self.save()?;
        Ok(())
    }

    /// get the fingerprint of the default key
    pub fn default_key_fingerprint(&mut self) -> Result<EncodedMultihash, Error> {
        if let Some(fingerprint) = self.keychain.default_key.clone() {
            Ok(fingerprint)
        } else {
            Err(Error::NoKey(String::default()))
        }
    }

    /// get default key
    pub fn default_key(&mut self) -> Result<Multikey, Error> {
        if let Some(fingerprint) = self.keychain.default_key.clone() {
            debug!("looking for key: {}", fingerprint.to_string());
            let key = self.keychain()?.borrow().get(&fingerprint)?;
            Ok(key)
        } else {
            Err(Error::NoKey(String::default()))
        }
    }

    /// Saves the config to disk
    pub fn save(&self) -> Result<(), Error> {
        let toml = toml::to_string(&self)?;
        let mut f = File::create(&self.path)?;
        f.write_all(toml.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //use super::*;
    //use toml;

    /*
    #[test]
    fn test_roundtrip() {
        let c1 = Config {
            keychain: KeychainConfig {
                default_key: None,
                keyfile: Some("./keyfile".to_string()),
                envvar: None,
                storage: Backend::LocalFile,
            },
        };
        let s = toml::to_string(&c1).unwrap();
        println!("{}", &s);
        let c2 = toml::from_str(&s).unwrap();
        println!("{:?}", c2);
        assert_eq!(c1, c2);
    }
    */
}
