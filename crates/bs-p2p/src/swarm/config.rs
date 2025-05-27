//! Configuration for the libp2p node for native target swarms

#![cfg(not(target_arch = "wasm32"))]
use libp2p::identity;
use libp2p::identity::Keypair;
use libp2p::identity::PeerId;
use libp2p_webrtc::tokio::Certificate;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

pub const LOCAL_KEY_PATH: &str = "local_keypair";

/// The configuration of the libp2p node.
#[derive(Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    pub identity: Identity,
}

impl zeroize::Zeroize for Config {
    fn zeroize(&mut self) {
        self.identity.peer_id.zeroize();
        self.identity.priv_key.zeroize();
        self.identity.cert_pem.zeroize();
    }
}

/// The identity of this node, the PeerId, priv key, and cert pem.
#[derive(Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Identity {
    pub peer_id: String,
    priv_key: Vec<u8>,
    cert_pem: String,
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn Error>> {
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }

    pub fn load(base_path: Option<PathBuf>) -> Result<(Keypair, Certificate), Box<dyn Error>> {
        let existing_keyfile = Config::from_file(Path::new(LOCAL_KEY_PATH)).ok();
        let key_path = PathBuf::from(LOCAL_KEY_PATH);
        let key_path = base_path.unwrap_or_default().join(key_path);

        tracing::info!("Loading Using Key path: {:?}", key_path);

        match existing_keyfile {
            Some(keyfile) => {
                tracing::info!("Previously saved local peerid available");

                let config = zeroize::Zeroizing::new(keyfile);
                let keypair = identity::Keypair::from_protobuf_encoding(&zeroize::Zeroizing::new(
                    config.identity.priv_key.clone(),
                ))?;

                let cert = Certificate::from_pem(&config.identity.cert_pem)?;

                let peer_id = keypair.public().into();
                assert_eq!(
                    PeerId::from_str(&config.identity.peer_id)?,
                    peer_id,
                    "Expect peer id derived from private key and peer id retrieved from config to match."
                );

                Ok((keypair, cert))
            }
            None => {
                tracing::info!("No local peerid available, generating new keypair");
                let keypair = identity::Keypair::generate_ed25519();
                let cert = Certificate::generate(&mut rand::thread_rng())?;
                let cert_pem = cert.serialize_pem();

                // Save keypair to file.
                let config = Config {
                    identity: Identity {
                        peer_id: keypair.public().to_peer_id().to_string(),
                        priv_key: keypair.to_protobuf_encoding().expect("valid keypair"),
                        cert_pem,
                    },
                };

                match serde_json::to_string_pretty(&config) {
                    Ok(config) => {
                        // write config to key_path,
                        // ensure the file and/or directory exists
                        // before writing to it.
                        tracing::info!("💾 Creating Key path: {:?}", key_path.parent().unwrap());
                        fs::create_dir_all(key_path.parent().unwrap())?;

                        //tracing::info!("💾 Creating Key path: {:?}", key_path);
                        //if let Err(e) = fs::create_dir_all(key_path.clone()) {
                        //    tracing::error!("⭕ Error creating key path: {:?}", e);
                        //}

                        tracing::info!("💾 Saving to Key path: {:?}", key_path);
                        if let Err(e) = fs::write(&key_path, config) {
                            tracing::error!("⭕ Error writing key path: {:?}", e);
                        }

                        tracing::info!("LOADED.");
                        Ok((keypair, cert))
                    }
                    Err(e) => Err(e.into()),
                }
            }
        }
    }

    /// Saves the keypair and certificate to the local filesystem.
    pub fn save(
        keypair: &Keypair,
        cert: &Certificate,
        base_path: Option<PathBuf>,
    ) -> Result<(), Box<dyn Error>> {
        let config = Config {
            identity: Identity {
                peer_id: keypair.public().to_peer_id().to_string(),
                priv_key: keypair.to_protobuf_encoding().expect("valid keypair"),
                cert_pem: cert.serialize_pem(),
            },
        };

        let key_path = PathBuf::from(LOCAL_KEY_PATH);
        let joind = base_path.unwrap_or_default().join(key_path);

        tracing::info!("💾 Saving to Key path: {:?}", joind);

        fs::write(joind, serde_json::to_string_pretty(&config)?)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;
    use libp2p_webrtc::tokio::Certificate;
    use std::fs;

    #[test]
    fn test_roundtrip() {
        // saves a keypair and certificate to the local filesystem, then loads and checks if same
        let keypair = Keypair::generate_ed25519();
        let cert = Certificate::generate(&mut rand::thread_rng()).unwrap();

        let key_path = PathBuf::from(LOCAL_KEY_PATH);

        let _ = fs::remove_file(&key_path);

        Config::save(&keypair, &cert, None).unwrap();

        let (keypair2, cert2) = Config::load(None).unwrap();

        assert_eq!(
            keypair.to_protobuf_encoding().unwrap(),
            keypair2.to_protobuf_encoding().unwrap()
        );
        assert_eq!(cert, cert2);
    }
}
