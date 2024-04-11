// SPDX-License-Identifier: FSL-1.1
use crate::{error::SshError, Error, Keychain, KeyEntry};
use multicodec::Codec;
use multihash::EncodedMultihash;
use multikey::{mk, Multikey, Views};
use multisig::{ms, Multisig};
use multiutil::CodecInfo;
use ssh_agent_client_rs::Client;
use ssh_key::PublicKey;
use std::{cell::RefCell, convert::TryFrom, env, ffi::OsString, path::PathBuf};

const SSH_AUTH_SOCK: &'static str = "SSH_AUTH_SOCK";

/// Keychain struct
pub struct SshAgent {
    /// The env var name used
    pub sshagent: Option<String>,

    /// The sshagent client
    pub client: RefCell<Client>,
}

impl TryFrom<Option<String>> for SshAgent {
    type Error = Error;

    fn try_from(sshagent: Option<String>) -> Result<Self, Self::Error> {
        let sshagent = match sshagent {
            Some(sshagent) => sshagent,
            None => SSH_AUTH_SOCK.to_string(),
        };

        // get the unix socket path
        let p: OsString = env::var_os(&sshagent).ok_or(Error::InvalidEnv(sshagent.clone()))?;
        let path = PathBuf::from(p);

        // ssh agent connect
        let client = Client::connect(&path).map_err(|e| SshError::SshAgent(e.to_string()))?;

        // return
        Ok(Self {
            sshagent: Some(sshagent),
            client: RefCell::new(client),
        })
    }
}

/// Interface to the keychain
impl Keychain for SshAgent {
    fn list(&self) -> Result<Vec<KeyEntry>, Error> {
        let pubkeys = self
            .client
            .borrow_mut()
            .list_identities()
            .map_err(|e| SshError::SshAgent(e.to_string()))?;
        let mut keys = Vec::with_capacity(pubkeys.len());
        for pk in &pubkeys {
            if let Ok(mk) = mk::Builder::new_from_ssh_public_key(pk)?.try_build() {
                let fv = mk.fingerprint_view()?;
                keys.push(KeyEntry{
                    fingerprint: Some(fv.fingerprint(Codec::Sha3256)?.into()),
                    pubkey: mk.clone(),
                    threshold: 1,
                    secret_keys: Vec::default(),
                });
            }
        }
        Ok(keys)
    }

    fn get(&self, fingerprint: &EncodedMultihash) -> Result<KeyEntry, Error> {
        let haystack = self.list()?;
        // check for a match
        for key in &haystack {
            let fv = key.pubkey.fingerprint_view()?;
            if *fingerprint == fv.fingerprint(fingerprint.codec())?.into() {
                return Ok(key.clone());
            }
        }
        Err(Error::NoKey(fingerprint.to_string()))
    }

    fn add(&mut self, _key: &KeyEntry) -> Result<(), Error> {
        Err(SshError::AddingKeysNotAllowed.into())
    }

    fn sign(
        &mut self,
        key: &Multikey,
        combined: bool,
        msg_encoding: Codec,
        msg: &[u8],
    ) -> Result<Multisig, Error> {
        // make sure we have a public key
        let attr = key.attr_view()?;
        if !attr.is_public_key() {
            return Err(SshError::NotPublicKey.into());
        }

        // generate an ssh public key from the key data
        let data = key.data_view()?;
        let key_bytes = data.key_bytes()?;
        let public_key =
            PublicKey::from_bytes(key_bytes.as_slice()).map_err(|e| SshError::SshKey(e))?;

        // send a sign request to the ssh agent
        match self.client.borrow_mut().sign(&public_key, msg) {
            Ok(s) => {
                if combined {
                    Ok(ms::Builder::new_from_ssh_signature(&s)?
                        .with_payload_encoding(msg_encoding)
                        .with_message_bytes(&msg)
                        .try_build()?)
                } else {
                    Ok(ms::Builder::new_from_ssh_signature(&s)?
                        .with_payload_encoding(msg_encoding)
                        .try_build()?)
                }
            }
            Err(e) => Err(SshError::SshAgent(e.to_string()).into()),
        }
    }
}
