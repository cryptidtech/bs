// SPDX-License-Identifier: FSL-1.1

/// Config for the open operation
pub mod config;
pub use config::Config;

use crate::{
    error::{BsCompatibleError, OpenError},
    update::{op, OpParams},
};
use multicid::{cid, vlad, Cid};
use multihash::mh;
use multikey::{Multikey, Views};
use provenance_log::{entry, error::EntryError, Error as PlogError, Log, OpId};
use tracing::debug;

/// open a new provenance log based on the config
pub fn open_plog<E: BsCompatibleError>(
    config: &Config,
    key_manager: &dyn crate::config::sync::KeyManager<E>,
    signer: &dyn crate::config::sync::MultiSigner<E>,
) -> Result<Log, E> {
    // 0. Set up the list of ops we're going to add
    let mut op_params = Vec::default();

    // go through the additional ops and generate CIDs and keys and adding the resulting op params
    // to the vec of op params
    config
        .additional_ops
        .iter()
        .try_for_each(|params| -> Result<(), E> {
            match params {
                p @ OpParams::KeyGen { .. } => {
                    let _ = load_key::<E>(&mut op_params, p, key_manager)?;
                }
                p @ OpParams::CidGen { .. } => {
                    let _ = load_cid::<E>(&mut op_params, p)?;
                }
                p => op_params.push(p.clone()),
            }
            Ok(())
        })?;

    // 1. Construct the VLAD from provided parameters

    // get the codec for the vlad signing key and cid
    let (vlad_key_params, vlad_cid_params) = &config.vlad_params;
    // get the vlad signing key
    let vlad_mk = load_key::<E>(&mut op_params, vlad_key_params, key_manager)?;
    // get the cid for the first lock script
    let cid = load_cid::<E>(&mut op_params, vlad_cid_params)?;

    let vlad = vlad::Builder::default()
        .with_signing_key(&vlad_mk)
        .with_cid(&cid)
        .try_build(|cid| {
            // get the serialized version of the vlad with an empty "proof" field
            let vlad_bytes: Vec<u8> = cid.clone().into();
            // sign the vlad bytes
            let multisig = signer.try_sign(&vlad_mk, &vlad_bytes).map_err(|e| {
                multicid::Error::Multisig(multisig::Error::SignFailed(e.to_string()))
            })?;
            Ok(multisig.into())
        })?;

    // 2. Call back to get the entry and pub keys and load the lock and unlock scripts

    // get the params for the entry signing key
    let entrykey_params = &config.entrykey_params;

    // get the entry signing key
    let entry_mk = load_key::<E>(&mut op_params, entrykey_params, key_manager)?;

    // get the params for the pubkey
    let pubkey_params = &config.pubkey_params;

    // get the pubkey
    let _ = load_key::<E>(&mut op_params, pubkey_params, key_manager)?;

    let lock_script = config.entry_lock_script.clone();
    let unlock_script = config.entry_unlock_script.clone();

    // 3. Construct the first entry, calling back to get the entry signed

    // construct the first entry from all of the parts
    let mut builder = entry::Builder::default()
        .with_vlad(&vlad)
        .add_lock(&lock_script)
        .with_unlock(&unlock_script);

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
        let ms = signer
            .try_sign(&entry_mk, &ev)
            .map_err(|e| PlogError::from(EntryError::SignFailed(e.to_string())))?;
        // store the signature as proof
        Ok(ms.into())
    })?;

    // 4. Construct the log

    let log = provenance_log::log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&config.first_lock_script)
        .append_entry(&entry)
        .try_build()?;

    Ok(log)
}

fn load_key<E>(
    ops: &mut Vec<OpParams>,
    params: &OpParams,
    key_manager: &dyn crate::config::sync::KeyManager<E>,
) -> Result<Multikey, E>
where
    E: From<OpenError> + From<multikey::Error> + From<crate::Error>,
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
            let pk = if mk.attr_view()?.is_secret_key() {
                mk.conv_view()?.to_public_key()?
            } else {
                mk.clone()
            };

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

fn load_cid<E>(ops: &mut Vec<OpParams>, params: &OpParams) -> Result<Cid, E>
where
    E: From<OpenError> + From<multihash::Error> + From<multicid::Error> + From<PlogError>,
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
                    data: data.to_vec(),
                });
            }

            Ok(cid)
        }
        _ => Err(OpenError::InvalidCidParams.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{entry_key::EntryKeyParams, pubkey::PubkeyParams, vlad::VladParams};

    use bs_wallets::memory::InMemoryKeyManager;
    use multikey::Multikey;
    use provenance_log::entry::Field;
    use provenance_log::format_with_fields;
    use provenance_log::value::try_extract;
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

        let config = Config {
            vlad_params: VladParams::default().into(),
            pubkey_params: PubkeyParams::default().into(),
            entrykey_params: EntryKeyParams::default().into(),
            first_lock_script: Script::Code(Key::default(), VladParams::FIRST_LOCK_SCRIPT.into()),
            entry_lock_script: Script::Code(Key::default(), lock),
            entry_unlock_script: Script::Code(Key::default(), unlock),
            additional_ops: vec![],
        };

        let key_manager = InMemoryKeyManager::<crate::Error>::default();
        let plog = open_plog(&config, &key_manager, &key_manager).expect("Failed to open plog");

        // log.first_lock should match
        assert_eq!(plog.first_lock, config.first_lock_script);

        // 1. Get vlad_key from plog first entry
        let verify_iter = &mut plog.verify();

        // the log should also verify
        for ret in verify_iter {
            if let Some(e) = ret.err() {
                tracing::error!("Error: {:#?}", e);
                // fail test
                panic!("Error in log verification");
            }
        }

        // TODO: This API could be improved
        let (_count, _entry, kvp) = &mut plog.verify().next().unwrap().unwrap();

        let vlad_key_value = kvp.get(VladParams::KEY_PATH).unwrap();
        let vlad_key: Multikey = try_extract(&vlad_key_value).unwrap();

        assert_eq!(&vlad_key, key_manager.vlad());
        assert!(plog.vlad.verify(&vlad_key).is_ok());

        // /pubkey should match key_manager.entry_key public key
        let entry_key = kvp.get(PubkeyParams::KEY_PATH).unwrap();

        let entry_key: Multikey = try_extract(&entry_key).unwrap();

        let key_manager_pk = if key_manager.entry_key().attr_view().unwrap().is_secret_key() {
            key_manager
                .entry_key()
                .conv_view()
                .unwrap()
                .to_public_key()
                .unwrap()
        } else {
            key_manager.entry_key().clone()
        };
        assert_eq!(entry_key, key_manager_pk);
    }
}
