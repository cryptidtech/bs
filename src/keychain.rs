use crate::Error;
use core::{convert::TryFrom, fmt};
use multicodec::Codec;
use multihash::EncodedMultihash;
use multikey::Multikey;
use multisig::Multisig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Interface to the keychain
pub trait Keychain {
    /// list the available keys
    fn list(&self) -> Result<Vec<Multikey>, Error>;

    /// get a key by name
    fn get(&self, fingerprint: &EncodedMultihash) -> Result<Multikey, Error>;

    /// add a key
    fn add(&mut self, key: &Multikey) -> Result<(), Error>;

    /// sign a message with a key
    fn sign(
        &mut self,
        key: &Multikey, // the key to sign with
        combined: bool,
        msg_encoding: Codec, // the encoding for the message (e.g. cbor, json)
        msg: &[u8],          // the canonicalized and serialzied message to sign
    ) -> Result<Multisig, Error>;
}

/// Keychain config
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeychainConfig {
    /// Default key name
    pub default_key: Option<EncodedMultihash>,

    /// Optional file for storing keys if storage is "file"
    pub keyfile: Option<PathBuf>,

    /// Optional env var if storage is "sshagent"
    pub sshagent: Option<String>,

    /// Keychain
    pub storage: Backend,
}

impl KeychainConfig {
    /// Creates a new keychain config
    pub fn new(keyfile: Option<PathBuf>, sshagent: bool, sshagentenv: String) -> Self {
        let storage = {
            if sshagent {
                Backend::SshAgent
            } else {
                Backend::LocalFile
            }
        };

        Self {
            default_key: None,
            keyfile,
            sshagent: Some(sshagentenv),
            storage,
        }
    }
}

/// The keychain backend
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum Backend {
    /// The keychain is a local file
    LocalFile,

    /// The keychain is an ssh agent
    SshAgent,
}

impl TryFrom<String> for Backend {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "file" => Ok(Backend::LocalFile),
            "ssh-agent" => Ok(Backend::SshAgent),
            _ => return Err(Error::InvalidBackendType(s)),
        }
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Backend::LocalFile => "file".to_string(),
                Backend::SshAgent => "ssh-agent".to_string(),
            }
        )
    }
}

impl Into<String> for Backend {
    fn into(self) -> String {
        self.to_string()
    }
}
