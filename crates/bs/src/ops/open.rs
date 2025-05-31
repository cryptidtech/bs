// SPDX-License-Identifier: FSL-1.1

/// Config for the open operation
pub mod config;
use crate::{
    error::{BsCompatibleError, OpenError},
    update::{op, OpParams},
};
pub use config::Config;
use multicid::{cid, vlad, Cid};
use multicodec::Codec;
use multihash::mh;
use multikey::{Multikey, Views};
use provenance_log::{entry, error::EntryError, Error as PlogError, Log, OpId};
use tracing::debug;

/// open a new provenance log based on the config
//
// To Open a Plog, the critical steps are:
// - First get the public key of the ephemeral first entry key
// - Add the public key of the ephemeral first entry key operation to `op_params`
// - Add ALL operations to the entry builder
// - Sign that operated entry using the ephemeral first entry key's one-time signing function
// - Finalize the Entry with the signature
//
// When the script runtime checks the first entry data (the Entry without the proof), against the
//
pub fn open_plog<E: BsCompatibleError>(
    config: &Config,
    key_manager: &dyn crate::config::sync::KeyManager<E>,
    signer: &dyn crate::config::sync::MultiSigner<E>,
) -> Result<Log, E> {
    // 0. Set up the list of ops
    let mut op_params = Vec::default();

    // Process initial operations
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

    // 1. Extract VLAD parameters and prepare signing
    let (vlad_key_params, vlad_cid_params) = &config.vlad_params;
    let (codec, threshold, limit) = extract_key_params::<E>(vlad_key_params)?;

    // Use prepare_ephemeral_signing to get public key and signing function
    let (vlad_pubkey, sign_vlad) = signer.prepare_ephemeral_signing(&codec, threshold, limit)?;

    let cid = load_cid::<E>(&mut op_params, vlad_cid_params)?;

    // Add the VLAD public key operation to op_params
    if let OpParams::KeyGen { key, .. } = vlad_key_params {
        op_params.push(OpParams::UseKey {
            key: key.clone(),
            mk: vlad_pubkey.clone(),
        });
    }

    // Build the VLAD using the public key
    let vlad = vlad::Builder::default()
        .with_signing_key(&vlad_pubkey)
        .with_cid(&cid)
        .try_build(|cid, _| {
            let vlad_cid_bytes: Vec<u8> = cid.clone().into();
            let multisig = sign_vlad(&vlad_cid_bytes).map_err(|e| {
                tracing::error!("VLAD multisig sign failed: {:?}", e);
                multicid::Error::Multisig(multisig::Error::SignFailed(e.to_string()))
            })?;
            Ok(multisig.into())
        })?;

    // 2. Extract entry key parameters and prepare signing
    let entrykey_params = &config.entrykey_params;
    let (codec, threshold, limit) = extract_key_params::<E>(entrykey_params)?;

    // Get the public key and signing function
    let (entry_pubkey, sign_entry) = signer.prepare_ephemeral_signing(&codec, threshold, limit)?;

    // 3. Add the entry public key operation to op_params
    if let OpParams::KeyGen { key, .. } = entrykey_params {
        op_params.push(OpParams::UseKey {
            key: key.clone(),
            mk: entry_pubkey.clone(),
        });
    }

    // 4. Continue with other preparations
    let _ = load_key::<E>(&mut op_params, &config.pubkey_params, key_manager)?;
    let lock_script = config.entry_lock_script.clone();
    let unlock_script = config.entry_unlock_script.clone();

    // 5. Create the builder and add operations
    let mut builder = entry::Builder::new();
    builder
        .with_vlad(&vlad)
        .add_lock(&lock_script)
        .with_unlock(&unlock_script);

    // 6. Add ALL operations to builder (including entry public key)
    for params in &op_params {
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

        builder.add_op(&op);
    }

    // 7. Prepare entry for signing
    let unsigned_entry = builder.prepare_unsigned_entry()?;
    let entry_bytes: Vec<u8> = unsigned_entry.clone().into();

    // 8. Sign the entry using our one-time signing function
    let signature = sign_entry(&entry_bytes)
        .map_err(|e| PlogError::from(EntryError::SignFailed(e.to_string())))?;

    // 9. Finalize entry with signature
    let entry = builder.finalize_with_proof(signature.into())?;

    // 10. Construct the log
    let log = provenance_log::log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&config.first_lock_script)
        .append_entry(&entry)
        .try_build()?;

    Ok(log)
}

/// Helper function to extract parameters from OpParams
fn extract_key_params<E: BsCompatibleError>(params: &OpParams) -> Result<(Codec, usize, usize), E> {
    match params {
        OpParams::KeyGen {
            codec,
            threshold,
            limit,
            ..
        } => Ok((*codec, *threshold, *limit)),
        _ => Err(OpenError::InvalidKeyParams.into()),
    }
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
    use crate::params::anykey::EntryKeyParams;
    use crate::params::{pubkey::PubkeyParams, vlad::VladParams};

    use bs_wallets::memory::InMemoryKeyManager;
    use multikey::Multikey;
    use provenance_log::entry::Field;
    use provenance_log::format_with_fields;
    use provenance_log::key::util::KeyParamsType;
    use provenance_log::value::try_extract;
    use provenance_log::Script;
    use provenance_log::{Key, Pairs};
    use tracing_subscriber::fmt;

    #[allow(unused)]
    fn init_logger() {
        let subscriber = fmt().with_env_filter("debug,provenance_log=off").finish();
        if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
            tracing::warn!("failed to set subscriber: {}", e);
        }
    }

    #[test]
    fn test_create_using_defaults() {
        init_logger();

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
            entrykey_params: EntryKeyParams::default_params().into(),
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

        tracing::debug!("kvp: {:#?}", kvp);

        let vlad_key_value = kvp.get(VladParams::KEY_PATH).unwrap();
        let vlad_key: Multikey = try_extract(&vlad_key_value).unwrap();

        assert!(plog.vlad.verify(&vlad_key).is_ok());

        let entry_key = kvp.get(PubkeyParams::KEY_PATH).unwrap();

        assert!(try_extract::<Multikey>(&entry_key)
            .unwrap()
            .attr_view()
            .unwrap()
            .is_public_key());

        // should match thhe one we've got?
    }
}
