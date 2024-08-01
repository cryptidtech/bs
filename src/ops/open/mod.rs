// SPDX-License-Identifier: FSL-1.1

/// Config for the open operation
pub mod config;
pub use config::Config;

use crate::{
    error::OpenError,
    update::{op, script, OpParams},
    Error,
};
use log::debug;
use multicid::{cid, vlad, Cid};
use multicodec::Codec;
use multihash::mh;
use multikey::{Multikey, Views};
use multisig::Multisig;
use provenance_log::{entry, error::EntryError, Error as PlogError, Key, Log, OpId, Script};
use std::{fs::read, path::Path};

/// open a new provenanc log based on the config
pub fn open_plog<F1, F2>(config: Config, get_key: F1, sign_entry: F2) -> Result<Log, Error>
where
    F1: Fn(&Key, Codec, usize, usize) -> Result<Multikey, Error>,
    F2: Fn(&Multikey, &[u8]) -> Result<Multisig, Error>,
{
    // 0. Set up the list of ops we're going to add
    let mut op_params = Vec::default();

    // go through the additional ops and generate CIDs and keys and adding the resulting op params
    // to the vec of op params
    config
        .additional_ops
        .iter()
        .try_for_each(|params| -> Result<(), Error> {
            match params {
                p @ OpParams::KeyGen { .. } => {
                    let _ = load_key(&mut op_params, p, &get_key)?;
                }
                p @ OpParams::CidGen { .. } => {
                    let _ = load_cid(&mut op_params, p, |path| -> Result<Vec<u8>, Error> {
                        Ok(read(path)?)
                    })?;
                }
                p => op_params.push(p.clone()),
            }
            Ok(())
        })?;

    // 1. Construct the VLAD from provided parameters

    // get the codec for the vlad signing key and cid
    let (vlad_key_params, vlad_cid_params) = config
        .vlad_params
        .ok_or::<Error>(OpenError::InvalidVladParams.into())?;
    // get the vlad signing key
    let vlad_mk = load_key(&mut op_params, &vlad_key_params, &get_key)?;
    // get the cid for the first lock script
    let mut first_lock_script: Option<Script> = None;
    let cid = load_cid(
        &mut op_params,
        &vlad_cid_params,
        |path| -> Result<Vec<u8>, Error> {
            // this is a script so load the file that way
            let script = script::Loader::new(path).try_build()?;
            first_lock_script = Some(script.clone());
            Ok(script.into())
        },
    )?;

    // construct the signed vlad using the vlad pubkey and the first lock script cid
    let vlad = vlad::Builder::default()
        .with_signing_key(&vlad_mk)
        .with_cid(&cid)
        .try_build()?;

    // 2. Call back to get the entry and pub keys and load the lock and unlock scripts

    // get the params for the entry signing key
    let entrykey_params = config
        .entrykey_params
        .ok_or::<Error>(OpenError::InvalidKeyParams.into())?;

    // get the entry signing key
    let entry_mk = load_key(&mut op_params, &entrykey_params, &get_key)?;

    // get the params for the pubkey
    let pubkey_params = config
        .pubkey_params
        .ok_or::<Error>(OpenError::InvalidKeyParams.into())?;

    // get the pubkey
    let _ = load_key(&mut op_params, &pubkey_params, &get_key)?;

    // load the entry lock script
    let lock_script = {
        let lock_path = config
            .entry_lock_script
            .ok_or::<Error>(OpenError::NoEntryLockScript.into())?;
        script::Loader::new(&lock_path).try_build()?
    };

    // load the entry unlock script
    let unlock_script = {
        let unlock_path = config
            .entry_unlock_script
            .ok_or::<Error>(OpenError::NoEntryUnlockScript.into())?;
        script::Loader::new(&unlock_path).try_build()?
    };

    // 3. Construct the first entry, calling back to get the entry signed

    // construct the first entry from all of the parts
    let mut builder = entry::Builder::default()
        .with_vlad(&vlad)
        .add_lock(&lock_script)
        .with_unlock(&unlock_script);

    // add in all of the entry Ops
    op_params
        .iter()
        .try_for_each(|params| -> Result<(), Error> {
            // construct the op
            let op = match params {
                OpParams::Noop { key } => op::Builder::new(OpId::Noop)
                    .with_key_path(key)
                    .try_build()?,
                OpParams::Delete { key } => op::Builder::new(OpId::Delete)
                    .with_key_path(key)
                    .try_build()?,
                OpParams::UseCid { key, cid } => {
                    let v: Vec<u8> = cid.clone().into();
                    op::Builder::new(OpId::Update)
                        .with_key_path(key)
                        .with_data_value(v)
                        .try_build()?
                }
                OpParams::UseKey { key, mk } => {
                    let v: Vec<u8> = mk.clone().into();
                    op::Builder::new(OpId::Update)
                        .with_key_path(key)
                        .with_data_value(v)
                        .try_build()?
                }
                OpParams::UseStr { key, s } => op::Builder::new(OpId::Update)
                    .with_key_path(key)
                    .with_string_value(s)
                    .try_build()?,
                OpParams::UseBin { key, data } => op::Builder::new(OpId::Update)
                    .with_key_path(key)
                    .with_data_value(data)
                    .try_build()?,
                _ => return Err(OpenError::InvalidOpParams.into()),
            };
            // add the op to the builder
            builder = builder.clone().add_op(&op);
            Ok(())
        })?;

    // finalize the entry building by signing it
    let entry = builder.try_build(|e| {
        // get the serialzied version of the entry with an empty "proof" field
        let ev: Vec<u8> = e.clone().into();
        // call the call back to have the caller sign the data
        let ms = sign_entry(&entry_mk, &ev)
            .map_err(|e| PlogError::from(EntryError::SignFailed(e.to_string())))?;
        // store the signature as proof
        Ok(ms.into())
    })?;

    // 4. Construct the log

    let log = provenance_log::log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock_script.ok_or::<Error>(OpenError::NoFirstLockScript.into())?)
        .append_entry(&entry)
        .try_build()?;

    Ok(log)
}

fn load_key<F>(
    ops: &mut Vec<OpParams>,
    params: &OpParams,
    mut get_key: F,
) -> Result<Multikey, Error>
where
    F: FnMut(&Key, Codec, usize, usize) -> Result<Multikey, Error>,
{
    debug!("load_key: {:?}", params);
    match params {
        OpParams::KeyGen {
            key,
            codec,
            threshold,
            limit,
            revoke,
        } => {
            // call back to generate the key
            let mk = get_key(key, *codec, *threshold, *limit)?;

            // get the public key
            let pk = mk.conv_view()?.to_public_key()?;

            // if revoking, explicitly delete the old key first
            if *revoke {
                ops.push(OpParams::Delete { key: key.clone() });
            }

            // add the op params to add the key
            ops.push(OpParams::UseKey {
                key: key.clone(),
                mk: pk,
            });

            Ok(mk)
        }
        _ => Err(OpenError::InvalidKeyParams.into()),
    }
}

fn load_cid<F>(ops: &mut Vec<OpParams>, params: &OpParams, mut load_file: F) -> Result<Cid, Error>
where
    F: FnMut(&Path) -> Result<Vec<u8>, Error>,
{
    debug!("load_cid: {:?}", params);
    match params {
        OpParams::CidGen {
            key,
            version,
            target,
            hash,
            inline,
            path,
        } => {
            // load the file data for the cid
            let file_data = load_file(path)?;

            let cid = cid::Builder::new(*version)
                .with_target_codec(*target)
                .with_hash(&mh::Builder::new_from_bytes(*hash, &file_data)?.try_build()?)
                .try_build()?;

            // create the cid key-path
            let mut cid_key = key.clone();
            cid_key.push("/cid")?;

            // add the op params to add the cid for the file
            ops.push(OpParams::UseCid {
                key: cid_key,
                cid: cid.clone(),
            });

            // add the file directly to p.log if inline
            if *inline {
                // create the cid key-path
                let mut data_key = key.clone();
                data_key.push("/data")?;

                // add the op param to add the file data
                ops.push(OpParams::UseBin {
                    key: data_key,
                    data: file_data,
                });
            }

            Ok(cid)
        }
        _ => Err(OpenError::InvalidCidParams.into()),
    }
}
