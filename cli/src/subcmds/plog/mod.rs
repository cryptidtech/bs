// SPDX-License-Identifier: FSL-1.1

/// Plog command
pub mod command;
pub use command::Command;

use best_practices::cli::io::{reader, writer, writer_name};
use bs::{self, ops::{open, update}, update::OpParams};
use crate::{Config, Error, error::PlogError};
use log::debug;
use multibase::Base;
use multicid::{Cid, EncodedCid, EncodedVlad, Vlad};
use multicodec::Codec;
use multihash::EncodedMultihash;
use multikey::{EncodedMultikey, mk, Multikey, Views};
use multisig::Multisig;
use multiutil::{BaseEncoded, CodecInfo, DetectedEncoder, EncodingInfo};
use provenance_log::{Key, Log, Script};
use std::{collections::VecDeque, convert::TryFrom, path::PathBuf};
use wacc::Pairs;

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
            let cfg = open::Config::default()
                .with_pubkey_params(parse_key_params(&pub_key_params, Some("/pubkey"))?)
                .with_additional_ops(&mut build_key_params(&key_ops)?)
                .with_additional_ops(&mut build_string_params(&string_ops)?)
                .with_additional_ops(&mut build_file_params(&file_ops)?)
                .with_vlad_params(vlad_key, vlad_cid)
                .with_entrykey_params(parse_key_params(&entry_key_codec, Some("/entrykey"))?)
                .with_entry_lock_script(&lock_script_path)
                .with_entry_unlock_script(&unlock_script_path);

            // open the p.log
            let plog = open::open_plog(cfg,
                |key: &Key, codec: Codec, threshold: usize, limit: usize| -> Result<Multikey, bs::Error> {
                    debug!("Generating {} key ({} of {})...", codec, threshold, limit);
                    let mut rng = rand::rngs::OsRng::default();
                    let mk = mk::Builder::new_from_random_bytes(codec, &mut rng)?.try_build()?;
                    let fingerprint = mk.fingerprint_view()?.fingerprint(Codec::Blake3)?;
                    let ef = EncodedMultihash::from(fingerprint);
                    debug!("Writing {} key fingerprint: {}", key, ef);
                    let w = writer(&Some(format!("{}.multikey", ef).into()))?;
                    serde_cbor::to_writer(w, &mk)?;
                    Ok(mk)
                },
                |mk: &Multikey, data: &[u8]| -> Result<Multisig, bs::Error> {
                    debug!("Signing the first entry");
                    Ok(mk.sign_view()?.sign(data, false, None)?)
                },
            )?;

            println!("Created p.log {}", writer_name(&output)?.to_string_lossy());
            print_plog(&plog)?;
            let w = writer(&output)?;
            serde_cbor::to_writer(w, &plog)?;
        }

        Command::Print { input } => {
            let mut v = Vec::default();
            reader(&input)?.read_to_end(&mut v)?;
            let plog: Log = serde_cbor::from_slice(&v)?;
            //let plog: Log = serde_cbor::from_reader(reader(&input)?)?;
            println!("p.log");
            print_plog(&plog)?;
        }

        Command::Update {
            delete_ops,
            key_ops,
            string_ops,
            file_ops,
            unlock_script_path,
            entry_signing_key,
            output,
            input,
        } => {
            let mut plog = {
                let mut v = Vec::default();
                reader(&input)?.read_to_end(&mut v)?;
                serde_cbor::from_slice::<Log>(&v)?
            };

            let entry_signing_key = {
                let mut v = Vec::default();
                reader(&entry_signing_key)?.read_to_end(&mut v)?;
                serde_cbor::from_slice::<Multikey>(&v)?
            };

            let cfg = update::Config::default()
                .with_ops(&mut build_delete_params(&delete_ops)?)
                .with_ops(&mut build_key_params(&key_ops)?)
                .with_ops(&mut build_string_params(&string_ops)?)
                .with_ops(&mut build_file_params(&file_ops)?)
                .with_entry_signing_key(&entry_signing_key)
                .with_entry_unlock_script(&unlock_script_path);

            // update the p.log
            update::update_plog(&mut plog, cfg,
                |key: &Key, codec: Codec, threshold: usize, limit: usize| -> Result<Multikey, bs::Error> {
                    debug!("Generating {} key ({} of {})...", codec, threshold, limit);
                    let mut rng = rand::rngs::OsRng::default();
                    let mk = mk::Builder::new_from_random_bytes(codec, &mut rng)?.try_build()?;
                    let fingerprint = mk.fingerprint_view()?.fingerprint(Codec::Blake3)?;
                    let ef = EncodedMultihash::from(fingerprint);
                    debug!("Writing {} key fingerprint: {}", key, ef);
                    let w = writer(&Some(format!("{}.multikey", ef).into()))?;
                    serde_cbor::to_writer(w, &mk)?;
                    Ok(mk)
                },
                |mk: &Multikey, data: &[u8]| -> Result<Multisig, bs::Error> {
                    debug!("Signing the first entry");
                    Ok(mk.sign_view()?.sign(data, false, None)?)
                },
            )?;

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
    let vlad_key_value = kvp.get("/vlad/key").ok_or::<Error>(PlogError::NoVladKey.into())?;
    let vlad_key: Multikey = get_from_wacc_value(&vlad_key_value).ok_or::<Error>(PlogError::InvalidWaccValue.into())?;

    while let Some(ret) = vi.next() {
        match ret {
            Ok((_, _, ref pairs)) => kvp = pairs.clone(),
            Err(e) => debug!("verify failed: {}", e.to_string()),
        }
    }

    let vl: Vec<String> = format!("(vlad) {}", EncodedVlad::new(Base::Base32Z, plog.vlad.clone()))
        .chars()
        .collect::<Vec<_>>()
        .chunks(83)
        .map(|chunk| chunk.iter().collect())
        .collect();
    for l in &vl {
        println!("│  {}", l);
    }

    if plog.vlad.verify(&vlad_key).is_ok() {
        println!("│   ╰─ ☑ verified '/vlad/key' -> ({}) {}", vlad_key.codec(), EncodedMultikey::new(Base::Base32Z, vlad_key));
    } else {
        println!("│   ╰─ ☒ failed to verify");
    }
    println!("├─ entries {}", plog.entries.len());
    println!("╰─ kvp");
    let mut i = 0;
    for (k, v) in kvp.iter() {
        if i < kvp.len() - 1 {
            print!("    ├─ '{}' -> ", k);
        } else {
            print!("    ╰─ '{}' -> ", k);
        }
        if let Some(codec) = get_codec_from_plog_value(&v) {
            match codec {
                Codec::Multikey => {
                    let v = kvp.get(k.as_str()).ok_or::<Error>(PlogError::NoKeyPath.into())?;
                    let key: Multikey = get_from_wacc_value(&v)
                        .ok_or::<Error>(PlogError::InvalidWaccValue.into())?;
                    println!("({} key) {}", key.codec(), EncodedMultikey::new(Base::Base32Z, key.clone()));
                }
                Codec::Vlad => {
                    let v = kvp.get(k.as_str()).ok_or::<Error>(PlogError::NoKeyPath.into())?;
                    let vlad: Vlad = get_from_wacc_value(&v)
                        .ok_or::<Error>(PlogError::InvalidWaccValue.into())?;
                    println!("(vlad) {}", EncodedVlad::from(vlad.clone()));
                }
                Codec::ProvenanceLogScript => {
                    let v = kvp.get(k.as_str()).ok_or::<Error>(PlogError::NoKeyPath.into())?;
                    let script: Script = get_from_wacc_value(&v)
                        .ok_or::<Error>(PlogError::InvalidWaccValue.into())?;
                    println!("(script) {} bytes", script.as_ref().len());
                }
                Codec::Cidv1 | Codec::Cidv2 | Codec::Cidv3 => {
                    let v = kvp.get(k.as_str()).ok_or::<Error>(PlogError::NoKeyPath.into())?;
                    let cid: Cid = get_from_wacc_value(&v)
                        .ok_or::<Error>(PlogError::InvalidWaccValue.into())?;
                    println!("({}) {}", cid.codec(), EncodedCid::from(cid.clone()));
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
        i += 1;
    }
    /*
    let kvp_lines = kvp.to_string().lines().map(|s| s.to_string()).collect::<Vec<_>>();
    for i in 0..kvp_lines.len() {
        if i < kvp_lines.len() - 1 {
            println!("    ├─ {}", kvp_lines[i]);
        } else {
            println!("    ╰─ {}", kvp_lines[i]);
        }
    }
    */
    Ok(())
}

fn get_codec_from_plog_value(value: &provenance_log::Value) -> Option<Codec> {
    match value {
        provenance_log::Value::Data(v) => Codec::try_from(v.as_slice()).ok(),
        provenance_log::Value::Str(s) => Codec::try_from(s.as_str()).ok(),
        _ => None,
    }
}
/*
fn get_from_plog_value<'a, T>(value: &'a provenance_log::Value) -> Option<T>
where
    T: TryFrom<&'a [u8]> + EncodingInfo,
    BaseEncoded<T, DetectedEncoder>: TryFrom<&'a str>,
{
    match value {
        provenance_log::Value::Data(v) => T::try_from(v.as_slice()).ok(),
        provenance_log::Value::Str(s) => {
            match BaseEncoded::<T, DetectedEncoder>::try_from(s.as_str()) {
                Ok(be) => Some(be.to_inner()),
                Err(_) => None
            }
        }
        _ => None,
    }
}
*/

fn get_from_wacc_value<'a, T>(value: &'a wacc::Value) -> Option<T>
where
    T: TryFrom<&'a [u8]> + EncodingInfo,
    BaseEncoded<T, DetectedEncoder>: TryFrom<&'a str>,
{
    match value {
        wacc::Value::Bin(v) => T::try_from(v.as_slice()).ok(),
        wacc::Value::Str(s) => {
            match BaseEncoded::<T, DetectedEncoder>::try_from(s.as_str()) {
                Ok(be) => Some(be.to_inner()),
                Err(_) => None
            }
        }
        _ => None,
    }
}

// <key-path>
fn build_delete_params(ops: &Vec<String>) -> Result<Vec<OpParams>, Error> {
    Ok(ops.iter().filter_map(|s| parse_delete_params(&s).ok()).collect::<Vec<_>>())
}

// <key-path>:<codec>[:<threshold>:<limit>]
fn build_key_params(ops: &Vec<String>) -> Result<Vec<OpParams>, Error> {
    Ok(ops.iter().filter_map(|s| parse_key_params(&s, None).ok()).collect::<Vec<_>>())
}

// <key-path>:<string>
fn build_string_params(ops: &Vec<String>) -> Result<Vec<OpParams>, Error> {
    Ok(ops.iter().filter_map(|s| parse_string_params(&s).ok()).collect::<Vec<_>>())
}

/// <branch-key-path>:<file>[:<inline>:<target codec>:<hash codec>:<hash length in bits>]. 
fn build_file_params(ops: &Vec<String>) -> Result<Vec<OpParams>, Error> {
    Ok(ops.iter().filter_map(|s| parse_file_params(&s).ok()).collect::<Vec<_>>())
}

// <key-path>
fn parse_delete_params(s: &str) -> Result<OpParams, Error> {
    let key = Key::try_from(s)?;
    Ok(OpParams::Delete {
        key
    })
}

// <key-path>:<codec>[:<threshold>:<limit>:<revoke>]
fn parse_key_params(s: &str, key_path: Option<&str>) -> Result<OpParams, Error> {
    let mut parts = s.split(":").collect::<VecDeque<_>>();
    let key = match key_path {
        Some(s) => Key::try_from(s)?,
        None => Key::try_from(parts.pop_front().ok_or(PlogError::NoKeyPath)?)?,
    };
    let codec = parse_key_codec(&parts.pop_front().ok_or(PlogError::NoCodec)?)?;
    if !parts.is_empty() && !(parts.len() == 2 || parts.len() == 3) {
        return Err(PlogError::InvalidKeyParams.into());
    }
    let threshold = match parts.pop_front().unwrap_or("0").parse::<usize>() {
        Ok(n) => n,
        _ => 0,
    };
    let limit = match parts.pop_front().unwrap_or("0").parse::<usize>() {
        Ok(n) => n,
        _ => 0,
    };
    let revoke = match parts.pop_front().unwrap_or("false").parse::<bool>() {
        Ok(b) => b,
        _ => false,
    };
    Ok(OpParams::KeyGen {
        key,
        codec,
        threshold,
        limit,
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
        s: s.to_string()
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
    let path = PathBuf::from(parts.pop_front().ok_or(PlogError::NoInputFile)?);
    if !parts.is_empty() && parts.len() != 4 {
        return Err(PlogError::InvalidFileParams.into());
    }
    let inline = match parts.pop_front().unwrap_or("false").parse::<bool>() {
        Ok(b) => b,
        _ => false,
    };
    let target = match Codec::try_from(parts.pop_front().unwrap()) {
        Ok(c) => c,
        _ => Codec::Identity,
    };
    let hash = match parse_safe_hash_codec(parts.pop_front().unwrap(), parts.pop_front().unwrap()) {
        Ok(c) => c,
        _ => Codec::Blake3,
    };
    Ok(OpParams::CidGen {
        key,
        version: Codec::Cidv1,
        target,
        hash,
        inline,
        path
    })
}

/// <first lock script path>[:<signing key codec>:<cid hashing codec>[:<hash length in bits>]]
fn parse_vlad_params(s: &str) -> Result<(OpParams, OpParams), Error> {
    let mut parts = s.split(":").collect::<VecDeque<_>>();
    let path = PathBuf::from(parts.pop_front().ok_or(PlogError::NoInputFile)?);
    if !parts.is_empty() && !(parts.len() == 2 || parts.len() == 3) {
        return Err(PlogError::InvalidFileParams.into());
    }
    let codec = match Codec::try_from(parts.pop_front().unwrap_or_default()) {
        Ok(c) => c,
        _ => Codec::Ed25519Priv,
    };
    let hash = match parse_safe_hash_codec(parts.pop_front().unwrap_or_default(), parts.pop_front().unwrap_or_default()) {
        Ok(c) => c,
        _ => Codec::Blake3,
    };
    Ok((
        OpParams::KeyGen {
            key: Key::try_from("/vlad/key")?,
            codec,
            threshold: 0,
            limit: 0,
            revoke: false,
        },
        OpParams::CidGen {
            key: Key::try_from("/vlad/")?,
            version: Codec::Cidv1,
            target: Codec::Identity,
            hash,
            inline: true,
            path,
        }
    ))
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
