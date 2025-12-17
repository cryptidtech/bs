// SPDX-License-Identifier: FSL-1.1

/// Plog command
pub mod command;
use bs::params::vlad::VladParams;
use bs_traits::sync::{SyncGetKey, SyncPrepareEphemeralSigning, SyncSigner};
use bs_traits::{EphemeralKey, GetKey, Signer};
pub use command::Command;

use crate::{error::PlogError, Config, Error};
use best_practices::cli::io::{reader, writer, writer_name};
use bs::{
    self,
    ops::{open, update},
    update::OpParams,
};
use comrade::Pairs;
use multibase::Base;
use multicid::{Cid, EncodedCid, EncodedVlad, Vlad};
use multicodec::Codec;
use multihash::EncodedMultihash;
use multikey::{mk, Multikey, Views};
use multisig::Multisig;
use multiutil::{BaseEncoded, CodecInfo, DetectedEncoder, EncodingInfo};
use provenance_log::{Key, Log, Script};
use rng::StdRng;
use std::num::{NonZero, NonZeroUsize};
use std::{
    collections::{HashMap, VecDeque},
    convert::TryFrom,
};
use tracing::debug;

/// Cli KeyManager
#[derive(Clone, Debug, Default)]
struct KeyManager(HashMap<Key, Multikey>);

impl GetKey for KeyManager {
    type Key = Multikey;
    type KeyPath = Key;
    type Codec = Codec;
    type Error = Error;
}

impl SyncGetKey for KeyManager {
    fn get_key(
        &self,
        key_path: &Self::KeyPath,
        codec: &Self::Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> Result<Self::Key, Self::Error> {
        // Your implementation using crate::error::Error
        debug!("Generating {} key ({} of {})...", codec, threshold, limit);
        let mut rng = StdRng::from_os_rng();
        let mk = mk::Builder::new_from_random_bytes(*codec, &mut rng)?.try_build()?;
        let fingerprint = mk.fingerprint_view()?.fingerprint(Codec::Blake3)?;

        let ef = EncodedMultihash::new(Base::Base32Z, fingerprint);
        debug!("Writing {} key fingerprint: {}", key_path, ef);
        let w = writer(&Some(format!("{}.multikey", ef).into()))?;
        serde_cbor::to_writer(w, &mk)?; // This now works with ?
        Ok(mk)
    }
}

// EphemeralKey
impl EphemeralKey for KeyManager {
    type PubKey = Multikey;
}

// Implement the new SyncPrepareEphemeralSigning trait
impl SyncPrepareEphemeralSigning for KeyManager {
    type Codec = Codec;

    fn prepare_ephemeral_signing(
        &self,
        codec: &Self::Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> Result<
        (
            <Self as EphemeralKey>::PubKey,
            Box<dyn FnOnce(&[u8]) -> Result<<Self as Signer>::Signature, <Self as Signer>::Error> + Send>,
        ),
        <Self as Signer>::Error,
    > {
        debug!(
            "Preparing ephemeral signing with {} key ({} of {})...",
            codec, threshold, limit
        );

        // Generate a new key for signing
        let mut rng = StdRng::from_os_rng();
        let secret_key = mk::Builder::new_from_random_bytes(*codec, &mut rng)?
            .with_threshold(threshold)
            .with_limit(limit)
            .try_build()?;

        // Get the public key
        let public_key = secret_key.conv_view()?.to_public_key()?;

        // Create the signing closure that owns the secret key
        let sign_once: Box<dyn FnOnce(&[u8]) -> Result<<Self as Signer>::Signature, <Self as Signer>::Error> + Send> = Box::new(
            move |data: &[u8]| -> Result<<Self as Signer>::Signature, <Self as Signer>::Error> {
                debug!("Signing data with ephemeral key");
                let signature = secret_key.sign_view()?.sign(data, false, None)?;
                Ok(signature)
            },
        );

        Ok((public_key, sign_once))
    }
}

impl Signer for KeyManager {
    type KeyPath = Key;
    type Signature = Multisig;
    type Error = Error;
}

impl SyncSigner for KeyManager {
    fn try_sign(
        &self,
        key_path: &Self::KeyPath,
        data: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        let key = self
            .0
            .get(key_path)
            .ok_or(PlogError::NoKeyPresent(key_path.clone()))?;
        Ok(key.sign_view()?.sign(data, false, None)?)
    }
}

/// processes plog subcommands
pub async fn go(cmd: Command, _config: &Config) -> Result<(), Error> {
    match cmd {
        Command::Open {
            pub_key_params,
            key_ops,
            string_ops,
            file_ops,
            vlad_params,
            entry_key_codec,
            lock_script_path,
            unlock_script_path,
            output,
        } => {
            let (vlad_key, vlad_cid) = parse_vlad_params(&vlad_params)?;

            let OpParams::KeyGen {
                codec: vlad_key_codec,
                ..
            } = vlad_key
            else {
                return Err(PlogError::InvalidFileParams.into());
            };

            let OpParams::CidGen {
                hash: vlad_cid_hash,
                ..
            } = vlad_cid
            else {
                return Err(PlogError::InvalidFileParams.into());
            };

            let lock_script = Script::Code(
                Key::default(),
                std::fs::read_to_string(&lock_script_path).map_err(|_| PlogError::NoKeyPath)?,
            );
            let unlock_script = Script::Code(
                Key::default(),
                std::fs::read_to_string(&unlock_script_path).map_err(|_| PlogError::NoKeyPath)?,
            );

            let mut additional_ops = Vec::new();
            additional_ops.extend(build_key_params(&key_ops)?);
            additional_ops.extend(build_string_params(&string_ops)?);
            additional_ops.extend(build_file_params(&file_ops)?);

            let cfg = open::Config::builder()
                .pubkey(parse_key_params(&pub_key_params, Some("/pubkey"))?)
                .vlad(
                    VladParams::builder()
                        .key(vlad_key_codec)
                        .hash(vlad_cid_hash)
                        .build(),
                )
                .entrykey(parse_key_params(&entry_key_codec, Some("/entrykey"))?)
                .unlock(unlock_script)
                .lock(lock_script.clone())
                .additional_ops(additional_ops) // Add all operations at once
                .build();

            let key_manager = KeyManager::default();

            // open the p.log
            let plog = open::open_plog_sync(&cfg, &key_manager, &key_manager)?;

            println!("Created p.log {}", writer_name(&output)?.to_string_lossy());
            print_plog(&plog)?;
            let w = writer(&output)?;
            serde_cbor::to_writer(w, &plog)?;
        }

        Command::Print { input } => {
            let mut v = Vec::default();
            reader(&input)?.read_to_end(&mut v)?;
            let plog: Log = serde_cbor::from_slice(&v)?;
            println!("p.log");
            print_plog(&plog)?;
        }

        Command::Update {
            delete_ops,
            key_ops,
            string_ops,
            file_ops,
            lock_script_path,
            unlock_script_path,
            entry_signing_key,
            output,
            input,
        } => {
            debug!("p.log update");
            let mut plog = {
                let mut v = Vec::default();
                reader(&input)?.read_to_end(&mut v)?;
                serde_cbor::from_slice::<Log>(&v)?
            };
            debug!("read p.log");

            let lock_script = Script::Code(
                Key::default(),
                std::fs::read_to_string(&lock_script_path).map_err(|_| PlogError::NoKeyPath)?,
            );

            let unlock_script = {
                let mut v = Vec::default();
                reader(&Some(unlock_script_path))?.read_to_end(&mut v)?;
                Script::Code(Key::default(), String::from_utf8(v)?)
            };

            // Collect all operations first
            let mut entry_ops = Vec::new();
            entry_ops.extend(build_delete_params(&delete_ops)?);
            entry_ops.extend(build_key_params(&key_ops)?);
            entry_ops.extend(build_string_params(&string_ops)?);
            entry_ops.extend(build_file_params(&file_ops)?);

            // read the entry signing key from the path
            // on Ok, try into Key, and fail Plog::Error::NoKeyPath
            let entry_signing_key = match std::fs::read_to_string(&entry_signing_key) {
                Ok(s) => Key::try_from(s.trim())?,
                Err(_) => return Err(PlogError::NoKeyPath.into()),
            };

            let cfg = update::Config::builder()
                .add_entry_lock_scripts(vec![lock_script.clone()])
                .unlock(unlock_script)
                .entry_signing_key(entry_signing_key)
                .additional_ops(entry_ops)
                .build();

            let key_manager = KeyManager::default();

            // update the p.log
            update::update_plog_sync::<Error>(&mut plog, &cfg, &key_manager, &key_manager)?;

            println!("Writing p.log {}", writer_name(&output)?.to_string_lossy());
            print_plog(&plog)?;
            let w = writer(&output)?;
            serde_cbor::to_writer(w, &plog)?;
        }
        _ => {}
    }

    Ok(())
}

fn print_plog(plog: &Log) -> Result<(), Error> {
    // get the verifying iterator
    let mut vi = plog.verify();

    // process the first entry and get the results
    let (_, _, mut kvp) = vi.next().ok_or::<Error>(PlogError::NoFirstEntry.into())??;
    let vlad_key_value = kvp
        .get("/vlad/key")
        .ok_or::<Error>(PlogError::NoVladKey.into())?;
    let vlad_key: Multikey =
        get_from_wacc_value(&vlad_key_value).ok_or::<Error>(PlogError::InvalidWaccValue.into())?;

    for ret in vi {
        match ret {
            Ok((_, _, ref pairs)) => kvp = pairs.clone(),
            Err(e) => debug!("verify failed: {}", e.to_string()),
        }
    }

    let vl: Vec<String> = format!(
        "(vlad) {}",
        EncodedVlad::new(Base::Base32Z, plog.vlad.clone())
    )
    .chars()
    .collect::<Vec<_>>()
    .chunks(83)
    .map(|chunk| chunk.iter().collect())
    .collect();
    for l in &vl {
        println!("│  {}", l);
    }

    if plog.vlad.verify(&vlad_key).is_ok() {
        let fingerprint = vlad_key.fingerprint_view()?.fingerprint(Codec::Blake3)?;
        let ef = EncodedMultihash::new(Base::Base32Z, fingerprint);
        println!(
            "│   ╰─ ☑ verified '/vlad/key' -> ({}) {}",
            vlad_key.codec(),
            ef
        );
    } else {
        println!("│   ╰─ ☒ failed to verify");
    }
    println!("├─ entries {}", plog.entries.len());
    println!("╰─ kvp");
    for (i, (k, v)) in kvp.iter().enumerate() {
        if i < kvp.len() - 1 {
            print!("    ├─ '{}' -> ", k);
        } else {
            print!("    ╰─ '{}' -> ", k);
        }
        if let Some(codec) = get_codec_from_plog_value(v) {
            match codec {
                Codec::Multikey => {
                    let v = kvp
                        .get(k.as_str())
                        .ok_or::<Error>(PlogError::NoKeyPath.into())?;
                    let key: Multikey = get_from_wacc_value(&v)
                        .ok_or::<Error>(PlogError::InvalidWaccValue.into())?;
                    let fingerprint = key.fingerprint_view()?.fingerprint(Codec::Blake3)?;
                    let ef = EncodedMultihash::new(Base::Base32Z, fingerprint);
                    println!("({} key) {}", key.codec(), ef);
                }
                Codec::Vlad => {
                    let v = kvp
                        .get(k.as_str())
                        .ok_or::<Error>(PlogError::NoKeyPath.into())?;
                    let vlad: Vlad = get_from_wacc_value(&v)
                        .ok_or::<Error>(PlogError::InvalidWaccValue.into())?;
                    println!("(vlad) {}", EncodedVlad::new(Base::Base32Z, vlad.clone()));
                }
                Codec::ProvenanceLogScript => {
                    let v = kvp
                        .get(k.as_str())
                        .ok_or::<Error>(PlogError::NoKeyPath.into())?;
                    let script: Script = get_from_wacc_value(&v)
                        .ok_or::<Error>(PlogError::InvalidWaccValue.into())?;
                    println!("(script) {} bytes", script.as_ref().len());
                }
                Codec::Cidv1 | Codec::Cidv2 | Codec::Cidv3 => {
                    let v = kvp
                        .get(k.as_str())
                        .ok_or::<Error>(PlogError::NoKeyPath.into())?;
                    let cid: Cid = get_from_wacc_value(&v)
                        .ok_or::<Error>(PlogError::InvalidWaccValue.into())?;
                    println!(
                        "({}) {}",
                        cid.codec(),
                        EncodedCid::new(Base::Base32Z, cid.clone())
                    );
                }
                _ => println!("{}", codec),
            }
        } else {
            match v {
                provenance_log::Value::Data(v) => println!("data of length {}", v.len()),
                provenance_log::Value::Str(s) => println!("'{}'", s),
                _ => println!("Nil"),
            }
        }
    }

    Ok(())
}

fn get_codec_from_plog_value(value: &provenance_log::Value) -> Option<Codec> {
    match value {
        provenance_log::Value::Data(v) => Codec::try_from(v.as_slice()).ok(),
        provenance_log::Value::Str(s) => Codec::try_from(s.as_str()).ok(),
        _ => None,
    }
}

fn get_from_wacc_value<'a, T>(value: &'a comrade::Value) -> Option<T>
where
    T: TryFrom<&'a [u8]> + EncodingInfo,
    BaseEncoded<T, DetectedEncoder>: TryFrom<&'a str>,
{
    match value {
        comrade::Value::Bin {
            hint: _,
            data: ref v,
        } => T::try_from(v.as_slice()).ok(),
        comrade::Value::Str {
            hint: _,
            data: ref s,
        } => match BaseEncoded::<T, DetectedEncoder>::try_from(s.as_str()) {
            Ok(be) => Some(be.to_inner()),
            Err(_) => None,
        },
        _ => None,
    }
}

// <key-path>
fn build_delete_params(ops: &[String]) -> Result<Vec<OpParams>, Error> {
    Ok(ops
        .iter()
        .filter_map(|s| parse_delete_params(s).ok())
        .collect::<Vec<_>>())
}

// <key-path>:<codec>[:<threshold>:<limit>]
fn build_key_params(ops: &[String]) -> Result<Vec<OpParams>, Error> {
    Ok(ops
        .iter()
        .filter_map(|s| parse_key_params(s, None).ok())
        .collect::<Vec<_>>())
}

// <key-path>:<string>
fn build_string_params(ops: &[String]) -> Result<Vec<OpParams>, Error> {
    Ok(ops
        .iter()
        .filter_map(|s| parse_string_params(s).ok())
        .collect::<Vec<_>>())
}

/// <branch-key-path>:<file>[:<inline>:<target codec>:<hash codec>:<hash length in bits>].
fn build_file_params(ops: &[String]) -> Result<Vec<OpParams>, Error> {
    Ok(ops
        .iter()
        .filter_map(|s| parse_file_params(s).ok())
        .collect::<Vec<_>>())
}

// <key-path>
fn parse_delete_params(s: &str) -> Result<OpParams, Error> {
    let key = Key::try_from(s)?;
    Ok(OpParams::Delete { key })
}

// <key-path>:<codec>[:<threshold>:<limit>:<revoke>]
fn parse_key_params(s: &str, key_path: Option<&str>) -> Result<OpParams, Error> {
    let mut parts = s.split(":").collect::<VecDeque<_>>();
    let key = match key_path {
        Some(s) => Key::try_from(s)?,
        None => Key::try_from(parts.pop_front().ok_or(PlogError::NoKeyPath)?)?,
    };
    let codec = parse_key_codec(parts.pop_front().ok_or(PlogError::NoCodec)?)?;
    if !(parts.is_empty() || parts.len() == 2 || parts.len() == 3) {
        return Err(PlogError::InvalidKeyParams.into());
    }
    let threshold = parts
        .pop_front()
        .unwrap_or("0")
        .parse::<usize>()
        .unwrap_or_default();
    let limit = parts
        .pop_front()
        .unwrap_or("0")
        .parse::<usize>()
        .unwrap_or_default();
    let revoke = parts
        .pop_front()
        .unwrap_or("false")
        .parse::<bool>()
        .unwrap_or_default();
    Ok(OpParams::KeyGen {
        key,
        codec,
        threshold: NonZero::new(threshold).unwrap(),
        limit: NonZero::new(limit).unwrap(),
        revoke,
    })
}

/// <key-path>:<string>
fn parse_string_params(s: &str) -> Result<OpParams, Error> {
    let mut parts = s.split(":").collect::<VecDeque<_>>();
    let key = Key::try_from(parts.pop_front().ok_or(PlogError::NoKeyPath)?)?;
    let s = parts.pop_front().ok_or(PlogError::NoStringValue)?;
    Ok(OpParams::UseStr {
        key,
        s: s.to_string(),
    })
}

/// <branch-key-path>:<file>[:<inline>:<target codec>:<hash codec>:<hash length in bits>].
fn parse_file_params(s: &str) -> Result<OpParams, Error> {
    let mut parts = s.split(":").collect::<VecDeque<_>>();
    let key = Key::try_from(parts.pop_front().ok_or(PlogError::NoKeyPath)?)?;
    // must be a branch
    if !key.is_branch() {
        return Err(PlogError::InvalidKeyPath.into());
    }
    if !parts.is_empty() && parts.len() != 4 {
        return Err(PlogError::InvalidFileParams.into());
    }
    let inline = parts
        .pop_front()
        .unwrap_or("false")
        .parse::<bool>()
        .unwrap_or_default();
    let target = match Codec::try_from(parts.pop_front().unwrap_or("identity")) {
        Ok(c) => c,
        _ => Codec::Identity,
    };
    let hash = match parse_safe_hash_codec(
        parts.pop_front().unwrap_or("blake3"),
        parts.pop_front().unwrap_or("256"),
    ) {
        Ok(c) => c,
        _ => Codec::Blake3,
    };
    Ok(OpParams::CidGen {
        key,
        version: Codec::Cidv1,
        target,
        hash,
        inline,
        data: vec![], // TODO: Placeholder for actual data
    })
}

/// <first lock script path>[:<signing key codec>:<cid hashing codec>[:<hash length in bits>]]
fn parse_vlad_params(s: &str) -> Result<(OpParams, OpParams), Error> {
    let mut parts = s.split(":").collect::<VecDeque<_>>();
    if !(parts.is_empty() || parts.len() == 2 || parts.len() == 3) {
        return Err(PlogError::InvalidFileParams.into());
    }
    let codec = match Codec::try_from(parts.pop_front().unwrap_or_default()) {
        Ok(c) => c,
        _ => Codec::Ed25519Priv,
    };
    let hash = match parse_safe_hash_codec(
        parts.pop_front().unwrap_or_default(),
        parts.pop_front().unwrap_or_default(),
    ) {
        Ok(c) => c,
        _ => Codec::Blake3,
    };
    Ok((
        OpParams::KeyGen {
            key: Key::try_from("/vlad/key")?,
            codec,
            threshold: NonZero::new(0).unwrap(),
            limit: NonZero::new(0).unwrap(),
            revoke: false,
        },
        OpParams::CidGen {
            key: Key::try_from("/vlad/")?,
            version: Codec::Cidv1,
            target: Codec::Identity,
            hash,
            inline: true,
            data: vec![], // TODO: Placeholder for actual data
        },
    ))
}

fn parse_key_codec(s: &str) -> Result<Codec, Error> {
    Ok(match s.to_lowercase().as_str() {
        "eddsa" => Codec::Ed25519Priv,
        "es256k" => Codec::Secp256K1Priv,
        "blsg1" => Codec::Bls12381G1Priv,
        "blsg2" => Codec::Bls12381G2Priv,
        "lamport" => Codec::LamportMsig,
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
