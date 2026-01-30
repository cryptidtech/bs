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

pub const DEFAULT_CONFIG_FILENAME: &str = "bs_p2p_config.json";

/// The configuration of the libp2p node.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    /// The path where the config was loaded from or will be saved to
    pub path: PathBuf,
    pub identity: Identity,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            path: PathBuf::from(DEFAULT_CONFIG_FILENAME),
            identity: Identity::default(),
        }
    }
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
    /// Loads a Config from a file
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn Error>> {
        let config: Config = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        // Ensure the loaded config knows where it came from
        let mut config = config;
        config.path = path.to_path_buf();
        Ok(config)
    }

    /// Loads keypair and certificate from config file, or returns an error if not found.
    /// The base_path parameter specifies where to look for the config file.
    pub fn load(base_path: Option<PathBuf>) -> Result<(Keypair, Certificate), Box<dyn Error>> {
        let config_path = determine_config_path(base_path);
        tracing::info!("Loading configuration from: {:?}", config_path);

        let config = Config::from_file(&config_path)?;
        tracing::info!("Found existing configuration");

        let config = zeroize::Zeroizing::new(config);
        let keypair = identity::Keypair::from_protobuf_encoding(&zeroize::Zeroizing::new(
            config.identity.priv_key.clone(),
        ))?;

        let cert = Certificate::from_pem(&config.identity.cert_pem)?;

        // Verify the peer ID matches what we expect
        let peer_id = keypair.public().into();
        assert_eq!(
            PeerId::from_str(&config.identity.peer_id)?,
            peer_id,
            "Peer ID derived from private key doesn't match the stored peer ID."
        );

        Ok((keypair, cert))
    }

    /// Saves the keypair and certificate to the filesystem.
    /// The base_path parameter specifies where to save the config file.
    pub fn save(
        keypair: &Keypair,
        cert: &Certificate,
        base_path: Option<PathBuf>,
    ) -> Result<(), Box<dyn Error>> {
        let config_path = determine_config_path(base_path);

        let config = Config {
            path: config_path.clone(),
            identity: Identity {
                peer_id: keypair.public().to_peer_id().to_string(),
                priv_key: keypair.to_protobuf_encoding().expect("valid keypair"),
                cert_pem: cert.serialize_pem(),
            },
        };

        // Ensure the directory exists
        if let Some(parent) = config_path.parent() {
            tracing::info!("💾 Creating directory: {:?}", parent);
            fs::create_dir_all(parent)?;
        }

        tracing::info!("💾 Saving configuration to: {:?}", config_path);
        fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;

        Ok(())
    }
}

/// Helper function to determine the final config file path
fn determine_config_path(base_path: Option<PathBuf>) -> PathBuf {
    match base_path {
        Some(path) => {
            if path.is_dir() {
                path.join(DEFAULT_CONFIG_FILENAME)
            } else {
                path
            }
        }
        None => PathBuf::from(DEFAULT_CONFIG_FILENAME),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;
    use libp2p_webrtc::tokio::Certificate;
    use tempfile::TempDir;

    #[test]
    fn test_roundtrip() {
        let temp_dir = TempDir::new().unwrap();

        let keypair = Keypair::generate_ed25519();
        let cert = Certificate::generate(&mut rand::thread_rng()).unwrap();

        Config::save(&keypair, &cert, Some(temp_dir.path().to_path_buf())).unwrap();

        let (keypair2, cert2) = Config::load(Some(temp_dir.path().to_path_buf())).unwrap();

        assert_eq!(
            keypair.to_protobuf_encoding().unwrap(),
            keypair2.to_protobuf_encoding().unwrap()
        );
        assert_eq!(cert, cert2);
    }

    #[test]
    fn test_custom_path() {
        let temp_dir = TempDir::new().unwrap();

        let keypair = Keypair::generate_ed25519();
        let cert = Certificate::generate(&mut rand::thread_rng()).unwrap();

        Config::save(&keypair, &cert, Some(temp_dir.path().to_path_buf())).unwrap();

        let (loaded_keypair, loaded_cert) =
            Config::load(Some(temp_dir.path().to_path_buf())).unwrap();

        assert_eq!(
            keypair.to_protobuf_encoding().unwrap(),
            loaded_keypair.to_protobuf_encoding().unwrap()
        );
        assert_eq!(cert, loaded_cert);
    }

    #[test]
    fn test_path_handling() {
        let temp_dir = TempDir::new().unwrap();

        let expected_path = temp_dir.path().join(DEFAULT_CONFIG_FILENAME);
        let actual_path = determine_config_path(Some(temp_dir.path().to_path_buf()));
        assert_eq!(expected_path, actual_path);

        let file_path = temp_dir.path().join("bs_path_test.json");
        let actual_path = determine_config_path(Some(file_path.clone()));
        assert_eq!(file_path, actual_path);
    }
}
