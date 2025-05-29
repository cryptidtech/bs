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
use multicid::{cid, Cid};
use multihash::mh;
use multikey::{Multikey, Views};
use provenance_log::{
    entry::{self, Entry},
    error::EntryError,
    Error as PlogError, Log, OpId,
};
use std::{fs::read, path::Path};
use tracing::debug;

/// update a provenance log given the update config
pub fn update_plog<E>(
    plog: &mut Log,
    config: &Config,
    key_manager: &dyn crate::config::sync::KeyManager<E>,
    signer: &dyn crate::config::sync::MultiSigner<E>,
) -> Result<Entry, E>
where
    E: From<UpdateError>
        + From<PlogError>
        + From<std::io::Error>
        + From<multicid::Error>
        + From<multikey::Error>
        + From<multihash::Error>
        + From<crate::Error>
        + ToString
        + std::fmt::Debug,
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
                    let _ = load_key::<E>(&mut op_params, p, key_manager)?;
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
    let unlock_script = &config.entry_unlock_script;

    // get the entry signing key
    let entry_mk = &config.entry_signing_key;

    // 3. Construct the next entry, starting from the last, calling back to get the entry signed

    // construct the first entry from all of the parts
    let mut builder = entry::Builder::from(&last_entry).with_unlock(unlock_script);

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
            .try_sign(entry_mk, &ev)
            .map_err(|e| PlogError::from(EntryError::SignFailed(e.to_string())))?;
        // store the signature as proof
        Ok(ms.into())
    })?;

    // try to add the entry to the p.log
    plog.try_append(&entry)?;

    Ok(entry)
}

fn load_key<E>(
    ops: &mut Vec<OpParams>,
    params: &OpParams,
    key_manager: &dyn crate::config::sync::KeyManager<E>,
) -> Result<Multikey, E>
where
    E: From<UpdateError> + From<multikey::Error> + From<crate::Error>,
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

fn load_cid<F, E>(ops: &mut Vec<OpParams>, params: &OpParams, _load_file: F) -> Result<Cid, E>
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
            data,
        } => {
            let cid = cid::Builder::new(*version)
                .with_target_codec(*target)
                .with_hash(&mh::Builder::new_from_bytes(*hash, data)?.try_build()?)
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
                    data: data.clone(),
                });
            }

            Ok(cid)
        }
        _ => Err(UpdateError::InvalidCidParams.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{entry_key::EntryKeyParams, pubkey::PubkeyParams, vlad::VladParams};
    use crate::{open, open_plog};

    use bs_wallets::memory::InMemoryKeyManager;
    use provenance_log::entry::Field;
    use provenance_log::format_with_fields;
    use provenance_log::Script;
    use provenance_log::{Key, Pairs};
    use tracing_subscriber::fmt;

    #[allow(unused)]
    fn init_logger() {
        let subscriber = fmt().with_env_filter("trace,provenance_log=off").finish();
        if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
            tracing::warn!("failed to set subscriber: {}", e);
        }
    }

    #[test]
    fn test_create_using_defaults() {
        // init_logger();

        let entry_key = Field::ENTRY;
        assert_eq!(entry_key, "/entry/");

        let proof_key = Field::PROOF;
        assert_eq!(proof_key, "/entry/proof");

        let unlock_old_school = format!(
            r#"
             // push the serialized Entry as the message
             push("{entry_key}");

             // push the proof data
             push("{proof_key}");
        "#
        );

        let unlock = format_with_fields!(
            r#"
             // push the serialized Entry as the message
             push("{Field::ENTRY}");

             // push the proof data
             push("{Field::PROOF}");
        "#
        );

        assert_eq!(unlock_old_school, unlock);

        let unlock_script = Script::Code(Key::default(), unlock.to_string());

        let lock = format_with_fields!(
            r#"
                // then check a possible threshold sig...
                check_signature("/recoverykey", "{Field::ENTRY}") ||

                // then check a possible pubkey sig...
                check_signature("/pubkey", "{Field::ENTRY}") ||

                // then the pre-image proof...
                check_preimage("/hash")
            "#
        );

        let lock_script = Script::Code(Key::default(), lock);

        let config = open::Config {
            vlad_params: VladParams::default().into(),
            pubkey_params: PubkeyParams::default().into(),
            entrykey_params: EntryKeyParams::default().into(),
            first_lock_script: Script::Code(Key::default(), VladParams::FIRST_LOCK_SCRIPT.into()),
            entry_lock_script: lock_script.clone(),
            entry_unlock_script: Script::Code(Key::default(), unlock),
            additional_ops: vec![],
        };

        let key_manager = InMemoryKeyManager::<crate::Error>::default();
        let mut plog = open_plog(&config, &key_manager, &key_manager).expect("Failed to open plog");

        // 2. Update the p.log with a new entry
        // - add a lock Script
        // - remove the entrykey lock Script
        // - add an op
        let update_cfg = Config::new(unlock_script.clone(), key_manager.entry_key().clone())
            .with_ops(&[OpParams::Delete {
                key: Key::try_from(EntryKeyParams::KEY_PATH).unwrap(),
            }])
            // Entry lock scripts define conditions which must be met by the next entry in the plog for it to be valid.
            .add_lock_script(Key::try_from("/delegated/").unwrap(), lock_script)
            .build();

        let prev = plog.head.clone();

        // tak config and use update method with TestKeyManager to update the log
        update_plog(&mut plog, &update_cfg, &key_manager, &key_manager)
            .expect("Failed to update plog");

        // plog head prev should match prev
        assert_eq!(prev, plog.entries.get(&plog.head).unwrap().prev());

        // There should be no DEFAULT_ENTRYKEY kvp
        let verify_iter = &mut plog.verify();

        let mut last = None;

        // the log should also verify
        for ret in verify_iter {
            if let Some(e) = ret.clone().err() {
                tracing::error!("Error: {:#?}", e);
                // fail test
                panic!("Error in log verification");
            } else {
                last = Some(ret.ok().unwrap());
            }
        }

        let (_count, _entry, kvp) = last.ok_or("No last entry").unwrap();
        let op = kvp.get(EntryKeyParams::KEY_PATH);

        assert!(op.is_none());
    }
}
