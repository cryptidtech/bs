// SPDX-License-Identifier: FSL-1.1
use crate::{
    initialize_local_file, Backend, Error, KeyEntry, Keychain, KeychainConfig, LocalFile, SshAgent,
};
use multihash::EncodedMultihash;
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    convert::TryFrom,
    fs::{self, File},
    io::Write,
    path::PathBuf,
    rc::Rc,
};
use tracing::debug;

const CONFIG_FILE: &str = "config.toml";
const ORG_DIRS: &[&str; 3] = &["tech", "cryptid", "bettersign"];

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

    /// The ssh agent config passed in during Config init
    #[serde(skip)]
    ssh_config: SshConfig,

    /// Keychain config
    keychain: KeychainConfig,
}

#[derive(Clone, Default)]
struct SshConfig {
    use_agent: bool,
    sshagent: Option<String>,
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
        debug!(
            "Config::from_path({:?}, {:?}, {}, {})",
            path, keyfile, sshagent, sshagentenv
        );
        //initialize the bettersign config file if needed
        let use_agent = sshagent;
        let env_var = sshagentenv.clone();
        let config_path = initialize_local_file(path, ORG_DIRS, CONFIG_FILE, |pb| {
            debug!("creating default config: {}", pb.display());
            let keychain = KeychainConfig::new(keyfile, use_agent, env_var.clone());
            let config = Config {
                path: pb.clone(),
                handle: None,
                ssh_config: SshConfig {
                    use_agent,
                    sshagent: Some(env_var),
                },
                keychain,
            };
            let toml = toml::to_string(&config)?;
            let mut f = File::create(&pb)?;
            f.write_all(toml.as_bytes())?;
            Ok(())
        })?;

        debug!(
            "Loading config from: {}",
            config_path.as_os_str().to_string_lossy()
        );
        let toml = fs::read_to_string(&config_path)?;
        let mut config: Self = toml::from_str(&toml)?;
        config.path = config_path.clone();
        config.ssh_config = SshConfig {
            use_agent: sshagent,
            sshagent: Some(sshagentenv),
        };
        Ok(config)
    }

    /// Loads the actual keychain
    pub fn keychain(&mut self) -> Result<Rc<RefCell<dyn Keychain>>, Error> {
        if self.handle.is_none() {
            self.handle = {
                if self.ssh_config.use_agent || self.keychain.storage == Backend::SshAgent {
                    if let Ok(sshagent) = SshAgent::try_from(self.ssh_config.sshagent.clone()) {
                        Some(Rc::new(RefCell::new(sshagent)))
                    } else {
                        let sshagent = SshAgent::try_from(self.keychain.sshagent.clone())?;
                        Some(Rc::new(RefCell::new(sshagent)))
                    }
                } else {
                    let keyfile = LocalFile::try_from(self.keychain.keyfile.clone())?;
                    Some(Rc::new(RefCell::new(keyfile)))
                }
            };
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
    pub fn default_key(&mut self) -> Result<KeyEntry, Error> {
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
