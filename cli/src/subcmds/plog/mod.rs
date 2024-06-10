// SPDX-License-Identifier: FSL-1.1

/// Plog command
pub mod command;
pub use command::Command;

use best_practices::cli::io::writer;
use bs::{self, ops::open::{self, OpenKey}};
use crate::{Config, Error/*, error::PlogError*/};
use log::debug;
use multicid::EncodedVlad;
use multicodec::Codec;
use multihash::EncodedMultihash;
use multikey::{mk, Multikey, Views};
use multisig::Multisig;

/// processes plog subcommands
pub async fn go(cmd: Command, _config: &Config) -> Result<(), Error> {
    match cmd {
        Command::Open {
            vlad_key_codec,
            vlad_cid_codec,
            vlad_cid_len,
            entry_key_codec,
            pub_key_codec,
            first_lock_script_path,
            lock_script_path,
            unlock_script_path,
            output,
        } => {
            let cfg = open::Config::default()
                .with_vladkey_codec(parse_key_codec(&vlad_key_codec)?)
                .with_entrykey_codec(parse_key_codec(&entry_key_codec)?)
                .with_pubkey_codec(parse_reusable_only_key_codec(&pub_key_codec)?)
                .with_vlad_cid_hash_codec(parse_safe_hash_codec(&vlad_cid_codec, &vlad_cid_len)?)
                .with_first_lock_script(&first_lock_script_path)
                .with_entry_lock_script(&lock_script_path)
                .with_entry_unlock_script(&unlock_script_path);

            // open the log
            let log = open::open_plog(cfg,
                |key: OpenKey, codec: Codec| -> Result<Multikey, bs::Error> {
                    debug!("Generating {} key...", codec);
                    let mut rng = rand::rngs::OsRng::default();
                    let mk = mk::Builder::new_from_random_bytes(codec, &mut rng)?.try_build()?;
                    let fingerprint = mk.fingerprint_view()?.fingerprint(Codec::Blake3)?;
                    let ef = EncodedMultihash::from(fingerprint);
                    match key {
                        OpenKey::VladKey => debug!("Vlad signing key fingerprint: {}", ef),
                        OpenKey::EntryKey => debug!("Entry signing key fingerprint: {}", ef),
                        OpenKey::PubKey => debug!("Entry advertising pubkey: {}", ef),
                    }
                    Ok(mk)
                },
                |mk: &Multikey, data: &[u8]| -> Result<Multisig, bs::Error> {
                    debug!("Signing the first entry");
                    Ok(mk.sign_view()?.sign(data, false, None)?)
                },
            )?;

            let mut vi = log.verify();
            while let Some(ret) = vi.next() {
                if let Some(e) = ret.err() {
                    debug!("verify failed: {}", e.to_string());
                }
            }

            let ev = EncodedVlad::from(log.vlad.clone());
            debug!("\nSUCCESS!!");
            debug!("Created p.log...");
            debug!("\tVLAD: {}", ev);

            let w = writer(&output)?;
            serde_cbor::to_writer(w, &log)?;
        }
        _ => {}
    }

    Ok(())
}

fn parse_key_codec(s: &str) -> Result<Codec, Error> {
    Ok(match s.to_lowercase().as_str() {
        "eddsa" => Codec::Ed25519Priv,
        "es256k" => Codec::Secp256K1Priv,
        "blsg1" => Codec::Bls12381G1Priv,
        "blsg2" => Codec::Bls12381G2Priv,
        "lamport" => Codec::LamportPriv,
        _ => return Err(Error::InvalidKeyType(s.to_string())),
    })
}

fn parse_reusable_only_key_codec(s: &str) -> Result<Codec, Error> {
    Ok(match s.to_lowercase().as_str() {
        "eddsa" => Codec::Ed25519Priv,
        "es256k" => Codec::Secp256K1Priv,
        "blsg1" => Codec::Bls12381G1Priv,
        "blsg2" => Codec::Bls12381G2Priv,
        _ => return Err(Error::InvalidKeyType(s.to_string())),
    })
}

fn parse_safe_hash_codec(s: &str, l: &str) -> Result<Codec, Error> {
    Ok(match l.to_lowercase().as_str() {
        "256" => match s.to_lowercase().as_str() {
            "blake2b" => Codec::Blake2B256,
            "blake2s" => Codec::Blake2S256,
            "blake3" => Codec::Blake3,
            "sha2" => Codec::Sha2256,
            "sha3" => Codec::Sha3256,
            _ => return Err(Error::InvalidHashType(s.to_string(), l.to_string())),
        },
        "384" => match s.to_lowercase().as_str() {
            "blake2b" => Codec::Blake2B384,
            "blake3" => Codec::Blake3,
            "sha2" => Codec::Sha2384,
            "sha3" => Codec::Sha3384,
            _ => return Err(Error::InvalidHashType(s.to_string(), l.to_string())),
        },
        "512" => match s.to_lowercase().as_str() {
            "blake2b" => Codec::Blake2B512,
            "blake3" => Codec::Blake3,
            "sha2" => Codec::Sha2512,
            "sha3" => Codec::Sha3512,
            _ => return Err(Error::InvalidHashType(s.to_string(), l.to_string())),
        },
        _ => return Err(Error::InvalidHashType(s.to_string(), l.to_string())),
    })
}
