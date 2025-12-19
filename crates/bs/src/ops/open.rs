// SPDX-License-Identifier: FSL-1.1

/// Config for the open operation
pub mod config;
use std::num::NonZeroUsize;

use crate::{
    config::asynchronous::{KeyManager, MultiSigner},
    error::{BsCompatibleError, OpenError},
    params::vlad::{FirstEntryKeyParams, VladParams},
    update::{op, OpParams},
    Signature,
};
pub use config::Config;
use multicid::{cid, Cid, Vlad};
use multicodec::Codec;
use multihash::mh;
use multikey::{Multikey, Views};
use provenance_log::{entry, error::EntryError, Error as PlogError, Key, Log, OpId};
use tracing::debug;

/// Open a new provenance log based on the [Config] provided. (async)
pub async fn open_plog<E>(
    config: &Config,
    key_manager: &mut (dyn KeyManager<E> + Send + Sync),
    signer: &(dyn MultiSigner<E> + Send + Sync),
) -> Result<Log, E>
where
    E: BsCompatibleError + Send,
{
    open_plog_core(config, key_manager, signer).await
}

/// Synchronous version of [open_plog]
#[cfg(feature = "sync")]
pub fn open_plog_sync<E>(
    config: &Config,
    key_manager: &(dyn crate::config::sync::KeyManager<E> + Send + Sync),
    signer: &(dyn crate::config::sync::MultiSigner<E> + Send + Sync),
) -> Result<Log, E>
where
    E: BsCompatibleError + Send + Sync + 'static,
{
    use crate::config::adapters::{SyncToAsyncManager, SyncToAsyncSigner};

    let mut key_manager_adapter = SyncToAsyncManager::new(key_manager);
    let signer_adapter = SyncToAsyncSigner::new(signer);

    futures::executor::block_on(open_plog_impl(
        config,
        &mut key_manager_adapter,
        &signer_adapter,
    ))
}

/// Core function to open a provenance log based on the [Config] provided. (async)
pub(crate) async fn open_plog_core<E>(
    config: &Config,
    key_manager: &mut (dyn KeyManager<E> + Send + Sync),
    signer: &(dyn MultiSigner<E> + Send + Sync),
) -> Result<Log, E>
where
    E: BsCompatibleError + Send,
{
    open_plog_impl(config, key_manager, signer).await
}

/// Internal implementation that works with base async traits (for adapters)
async fn open_plog_impl<E, KM, S>(
    config: &Config,
    key_manager: &mut KM,
    signer: &S,
) -> Result<Log, E>
where
    E: BsCompatibleError + Send,
    KM: bs_traits::asyncro::AsyncKeyManager<E, Key = Multikey, KeyPath = Key, Codec = Codec>
        + ?Sized,
    S: bs_traits::asyncro::AsyncMultiSigner<Signature, E, PubKey = Multikey, Codec = Codec>
        + bs_traits::asyncro::AsyncSigner<KeyPath = Key, Signature = Signature, Error = E>
        + ?Sized,
{
    // 0. Set up the list of ops
    let mut op_params = Vec::default();

    // Process initial operations
    for params in config.additional_ops().iter() {
        match params {
            p @ OpParams::KeyGen { .. } => {
                let _ = load_key(&mut op_params, p, key_manager).await?;
            }
            p @ OpParams::CidGen { .. } => {
                let _ = load_cid::<E>(&mut op_params, p)?;
            }
            p => op_params.push(p.clone()),
        }
    }

    // 1. Extract VLAD parameters and prepare signing
    let (vlad_key_params, vlad_cid_params): (OpParams, OpParams) =
        config.vlad_params().clone().into();
    let (codec, threshold, limit) = extract_key_params::<E>(&vlad_key_params)?;

    // get ephemeral public key and one time signing function
    let (vlad_pubkey, sign_vlad) = signer
        .prepare_ephemeral_signing(&codec, threshold, limit)
        .await?;

    let cid = load_cid::<E>(&mut op_params, &vlad_cid_params)?;

    // Add the VLAD public key operation to op_params
    if let OpParams::KeyGen { key, .. } = vlad_key_params {
        op_params.push(OpParams::UseKey {
            key: key.clone(),
            mk: vlad_pubkey.clone(),
        });
    }

    // Build the VLAD using the public key
    let vlad = Vlad::generate(&cid, |cid| {
        let vlad_cid_bytes: Vec<u8> = cid.clone().into();
        let multisig = sign_vlad(&vlad_cid_bytes).map_err(|e| {
            tracing::error!("VLAD multisig sign failed: {:?}", e);
            multicid::Error::Multisig(multisig::Error::SignFailed(e.to_string()))
        })?;
        Ok(multisig.into())
    })?;

    // Pass vlad to the caller for any pre-processing
    key_manager.preprocess_vlad(&vlad).await?;

    // 2. Extract entry key parameters and prepare signing
    let entrykey_params = &config.entrykey();
    let (codec, threshold, limit) = extract_key_params::<E>(entrykey_params)?;

    // Get the public key and signing function
    let (entry_pubkey, sign_entry) = signer
        .prepare_ephemeral_signing(&codec, threshold, limit)
        .await?;

    // 3. Add the entry public key operation to op_params
    if let OpParams::KeyGen { key, .. } = entrykey_params {
        op_params.push(OpParams::UseKey {
            key: key.clone(),
            mk: entry_pubkey.clone(),
        });
    }

    // 4. Continue with other preparations
    let _ = load_key(&mut op_params, config.pubkey(), key_manager).await?;
    let lock_script = config.lock_script().clone();
    let unlock_script = config.unlock().clone();

    // 5. Create the builder and add operations
    let builder = entry::Entry::builder();
    let mut entry = builder
        .vlad(vlad)
        .locks(vec![lock_script])
        .unlock(unlock_script)
        .build();

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

        entry.add_op(&op);
    }

    // 7. Prepare entry for signing
    let unsigned_entry = entry.prepare_unsigned_entry()?;
    let entry_bytes: Vec<u8> = unsigned_entry.clone().into();

    // 8. Sign the entry using our one-time signing function
    let signature = sign_entry(&entry_bytes)
        .map_err(|e| PlogError::from(EntryError::SignFailed(e.to_string())))?;

    // 9. Finalize entry with signature
    let entry = unsigned_entry.try_build_with_proof(signature.into())?;

    // 10. Construct the log
    let log = provenance_log::log::Builder::new()
        .with_vlad(entry.vlad())
        .with_first_lock(config.first_lock())
        .append_entry(&entry)
        .try_build()?;

    Ok(log)
}

/// Helper function to extract parameters from OpParams
fn extract_key_params<E: BsCompatibleError>(
    params: &OpParams,
) -> Result<(Codec, NonZeroUsize, NonZeroUsize), E> {
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

async fn load_key<E, KM>(
    ops: &mut Vec<OpParams>,
    params: &OpParams,
    key_manager: &KM,
) -> Result<Multikey, E>
where
    E: From<OpenError> + From<multikey::Error> + From<crate::Error>,
    KM: bs_traits::asyncro::AsyncKeyManager<E, Key = Multikey, KeyPath = Key, Codec = Codec>
        + ?Sized,
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
            let mk = key_manager.get_key(key, codec, *threshold, *limit).await?;

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
                if key.as_str() == VladParams::<FirstEntryKeyParams>::CID_KEY.as_str() {
                    ops.push(OpParams::UseBin {
                        key: Key::try_from(VladParams::<FirstEntryKeyParams>::DATA_KEY.as_str())?,
                        data: data.to_vec(),
                    });
                } else {
                    let mut data_key = key.clone();
                    data_key.push("/data")?;

                    // add the op param to add the file data
                    ops.push(OpParams::UseBin {
                        key: data_key,
                        data: data.to_vec(),
                    });
                }
            }

            Ok(cid)
        }
        _ => Err(OpenError::InvalidCidParams.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{
        anykey::PubkeyParams,
        vlad::{FirstEntryKeyParams, VladParams},
    };

    use bs_wallets::memory::InMemoryKeyManager;
    use multikey::Multikey;
    use provenance_log::entry::Field;
    use provenance_log::format_with_fields;
    use provenance_log::key::key_paths::ValidatedKeyParams;
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
        // init_logger();

        let pubkey_params = PubkeyParams::builder().codec(Codec::Ed25519Priv).build();

        let pubkey_key_path = pubkey_params.key_path().as_str();
        assert_eq!(pubkey_key_path, "/pubkey");

        // or we could use the asoc const from which it is derived
        let pubkey_ket_path = &*PubkeyParams::KEY_PATH;
        assert_eq!(pubkey_ket_path, "/pubkey");

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

        // If we have just Fields, we can use format_with_fields! macro
        let unlock = format_with_fields!(
            r#"
               // push the serialized Entry as the message
               push("{Field::ENTRY}");

               // push the proof data
               push("{Field::PROOF}");
          "#
        );

        assert_eq!(unlock_old_school, unlock);

        // Note: The First Lock script is embedded in VladParams,
        // since it's tightly coupled to the first entry key,
        // first entry key_path, and the Vlad Cid,
        // so we don't need to define it here.

        // for now, if we have a mix of Fields and Strings, we can use format! macro
        let lock = format!(
            r#"
                  // check a possible threshold sig...
                  check_signature("/recoverykey", "{entry_key}") ||

                  // then check a possible pubkey sig...
                  check_signature("{pubkey_key_path}", "{entry_key}") ||

                  // then the pre-image proof...
                  check_preimage("/hash")
              "#
        );

        // The Type on VladParams ensures we use the same type for the first entry key
        // which is used to generate the first lock script in the VladParams.
        let vlad_params = VladParams::<FirstEntryKeyParams>::default();

        let entry_key_params = FirstEntryKeyParams::builder()
            .codec(Codec::Ed25519Priv)
            .build();

        let config = Config::builder() // Uses default type parameter FirstEntryKeyParams
            .vlad(vlad_params)
            .pubkey(pubkey_params.into())
            .entrykey(entry_key_params.into())
            .lock(Script::Code(Key::default(), lock))
            .unlock(Script::Code(Key::default(), unlock))
            .build();

        let key_manager = InMemoryKeyManager::<crate::Error>::default();

        let plog =
            open_plog_sync(&config, &key_manager, &key_manager).expect("Failed to open plog");

        // log.first_lock should match
        assert_eq!(&plog.first_lock, config.first_lock());

        // 1. Get vlad_key from plog first entry
        let binding = plog.clone();
        let verify_iter = &mut binding.verify();

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

        let vlad_key_value = kvp
            .get(&VladParams::<FirstEntryKeyParams>::KEY_PATH)
            .unwrap();
        let vlad_key: Multikey = try_extract(&vlad_key_value).unwrap();

        assert!(plog.vlad.verify(&vlad_key).is_ok());

        let entry_key = kvp.get(&PubkeyParams::KEY_PATH).unwrap();

        assert!(try_extract::<Multikey>(&entry_key)
            .unwrap()
            .attr_view()
            .unwrap()
            .is_public_key());

        // log the ops
        tracing::debug!("Ops in the log:");
        for (_cid, entry) in plog.entries {
            tracing::debug!("Entry");
            for op in entry.ops() {
                tracing::debug!("  Op: {:?}", op);
            }
        }

        // should match thhe one we've got?
    }
}
