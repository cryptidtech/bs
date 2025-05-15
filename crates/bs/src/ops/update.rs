// SPDX-License-Identifier: FSL-1.1

/// Utilities for building plog Op
pub mod op;
/// Utilities for building plog Script
pub mod script;

/// Config for the update operation
pub mod config;
pub use config::Config;

/// params for generating Op
pub mod op_params;
pub use op_params::OpParams;

use crate::error::UpdateError;
use bs_traits::{GetKey, Signer, SyncGetKey, SyncSigner};
use multicid::{cid, Cid};
use multicodec::Codec;
use multihash::mh;
use multikey::{Multikey, Views};
use multisig::Multisig;
use provenance_log::{
    entry::{self, Entry},
    error::EntryError,
    Error as PlogError, Key, Log, OpId,
};
use std::{fs::read, path::Path};
use tracing::debug;

/// update a provenance log given the update config
pub fn update_plog<G, S, E>(
    plog: &mut Log,
    config: Config,
    key_manager: &G,
    signer: &S,
) -> Result<Entry, E>
where
    G: GetKey<KeyPath = Key, Codec = Codec, Key = Multikey, Error = E> + SyncGetKey,
    S: Signer<Key = Multikey, Signature = Multisig, Error = E> + SyncSigner,
    E: From<UpdateError>
        + From<PlogError>
        + From<std::io::Error>
        + From<multicid::Error>
        + From<multikey::Error>
        + From<multihash::Error>
        + From<crate::Error>
        + ToString,
{
    // 0. Set up the list of ops we're going to add
    let mut op_params = Vec::default();

    // go through the additional ops and generate CIDs and keys and adding the resulting op params
    // to the vec of op params
    config
        .entry_ops
        .iter()
        .try_for_each(|params| -> Result<(), E> {
            match params {
                p @ OpParams::KeyGen { .. } => {
                    let _ = load_key(&mut op_params, p, key_manager)?;
                }
                p @ OpParams::CidGen { .. } => {
                    let _ = load_cid(&mut op_params, p, |path| -> Result<Vec<u8>, E> {
                        read(path).map_err(E::from)
                    })?;
                }
                p => op_params.push(p.clone()),
            }
            Ok(())
        })?;

    // 1. validate the p.log and get the last entry and state
    let (_, last_entry, _kvp) = plog.verify().last().ok_or(UpdateError::NoLastEntry)??;

    // 2. load the entry unlock script
    let unlock_script = {
        let unlock_path = config
            .entry_unlock_script
            .ok_or::<E>(UpdateError::NoEntryUnlockScript.into())?;
        script::Loader::new(unlock_path).try_build()?
    };

    // get the entry signing key
    let entry_mk = config
        .entry_signing_key
        .ok_or::<E>(UpdateError::NoSigningKey.into())?;

    // 3. Construct the next entry, starting from the last, calling back to get the entry signed

    // construct the first entry from all of the parts
    let mut builder = entry::Builder::from(&last_entry).with_unlock(&unlock_script);

    // add in all of the entry Ops
    op_params.iter().try_for_each(|params| -> Result<(), E> {
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
            _ => return Err(UpdateError::InvalidOpParams.into()),
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
        let ms = signer
            .try_sign(&entry_mk, &ev)
            .map_err(|e| PlogError::from(EntryError::SignFailed(e.to_string())))?;
        // store the signature as proof
        Ok(ms.into())
    })?;

    // try to add the entry to the p.log
    plog.try_append(&entry)?;

    Ok(entry)
}

fn load_key<G, E>(ops: &mut Vec<OpParams>, params: &OpParams, key_manager: &G) -> Result<G::Key, E>
where
    G: GetKey<Error = E, KeyPath = Key, Codec = Codec> + SyncGetKey,
    G::Key: Into<Vec<u8>> + Clone + Views,
    E: From<UpdateError> + From<multikey::Error>,
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
            let mk = key_manager.get_key(key, codec, *threshold, *limit)?;

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
        _ => Err(UpdateError::InvalidKeyParams.into()),
    }
}

fn load_cid<F, E>(ops: &mut Vec<OpParams>, params: &OpParams, load_file: F) -> Result<Cid, E>
where
    F: FnOnce(&Path) -> Result<Vec<u8>, E>,
    E: From<UpdateError> + From<multihash::Error> + From<multicid::Error> + From<PlogError>,
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
        _ => Err(UpdateError::InvalidCidParams.into()),
    }
}
