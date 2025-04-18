// SPDX-License-Identifier: FSL-1.1
use crate::Error;
use core::{convert::TryFrom, fmt};
use multicodec::Codec;
use multihash::EncodedMultihash;
use multikey::{Multikey, Views};
use multisig::Multisig;
use multiutil::{prelude::Base, CodecInfo};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A key entry in the keychain
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct KeyEntry {
    /// the fingerprint of the public key; used as the identifier of the key
    pub fingerprint: Option<EncodedMultihash>,
    /// the public key
    pub pubkey: Multikey,
    /// for non-threshold keys, this is 1, for threshold keys this is the threshold value
    pub threshold: usize,
    /// the list of generated secret keys. if the key is a threshold key then this list contains
    /// all of the secreet key shares. there should be `limit` number of them.
    pub secret_keys: Vec<Multikey>,
}

impl fmt::Display for KeyEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let kh = match self.fingerprint.clone() {
            Some(kh) => kh,
            None => {
                let fv = self.pubkey.fingerprint_view().unwrap();
                EncodedMultihash::new(Base::Base32Lower, fv.fingerprint(Codec::Sha3256).unwrap())
            }
        };

        let mut msg = String::default();

        if self.secret_keys.len() > 1 {
            msg.push_str(&format!("╭──── pubkey  {}\n", kh));
            msg.push_str(&format!("├───── codec  {}\n", self.pubkey.codec()));
            msg.push_str(&format!("├─── comment  {}\n", self.pubkey.comment));
            msg.push_str(&format!(
                "├─ threshold  {} of {}\n",
                self.threshold,
                self.secret_keys.len()
            ));
            msg.push_str("╰─┬── shares\n");
            for i in (0..self.secret_keys.len()).rev() {
                let skh = {
                    let cv = self.secret_keys[i].conv_view().unwrap();
                    let pk = cv.to_public_key().unwrap();
                    let fv = pk.fingerprint_view().unwrap();
                    EncodedMultihash::new(
                        Base::Base32Lower,
                        fv.fingerprint(Codec::Sha3256).unwrap(),
                    )
                };
                let key = format!(
                    "{} / {}  {}",
                    (self.secret_keys.len() - i),
                    self.secret_keys.len(),
                    skh
                );
                if i == 0 {
                    msg.push_str(&format!("  ╰─── {}\n", key));
                } else {
                    msg.push_str(&format!("  ├─── {}\n", key));
                }
            }
        } else {
            msg.push_str(&format!("╭──── pubkey  {}\n", kh));
            msg.push_str(&format!("├───── codec  {}\n", self.pubkey.codec()));
            msg.push_str(&format!("╰─── comment  {}\n", self.pubkey.comment));
        }

        write!(f, "{}", msg)
    }
}

/// Interface to the keychain
pub trait Keychain {
    /// list the available keys
    fn list(&self) -> Result<Vec<KeyEntry>, Error>;

    /// get a key by name
    fn get(&self, fingerprint: &EncodedMultihash) -> Result<KeyEntry, Error>;

    /// add a key
    fn add(&mut self, key: &KeyEntry) -> Result<(), Error>;

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
            _ => Err(Error::InvalidBackendType(s)),
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

impl From<Backend> for String {
    fn from(val: Backend) -> Self {
        val.to_string()
    }
}
