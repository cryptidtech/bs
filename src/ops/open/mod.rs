// SPDX-License-Identifier: FSL-1.1

/// Config for the open operation
pub mod config;
pub use config::Config;

use crate::{Error, error::OpenError};
use multicid::{cid, vlad};
use multicodec::Codec;
use multihash::mh;
use multikey::{Multikey, Views};
use multisig::Multisig;
use provenance_log::{entry, error::EntryError, Error as PlogError, log, Log, OpId};
use super::update::{op, script};

/// The key being asked for
#[derive(Clone, Debug)]
pub enum OpenKey {
    /// Asking for a VLAD signing key
    VladKey,
    /// Asking for an Entry signing key
    EntryKey,
    /// Asking for a key to publish in the Entry
    PubKey,
}

/// open a new provenanc log based on the config
pub fn open<F1, F2>(config: Config, get_key: F1, sign_entry: F2) -> Result<Log, Error>
where
    F1: Fn(OpenKey, Codec) -> Result<Multikey, Error>,
    F2: Fn(&Multikey, &[u8]) -> Result<Multisig, Error>,
{
    // 1. Call back to get the VLAD key, load the first lock script and construct the VLAD

    // get the codec for the vlad signing key and generate it
    let vladkey_codec = config.vladkey_codec.unwrap_or(Codec::Ed25519Priv);
    let vlad_mk = get_key(OpenKey::VladKey, vladkey_codec)?;

    // load the first lock script
    let first_lock_script = {
        let first_lock_path = config.first_lock_script.ok_or::<Error>(OpenError::NoFirstLockScript.into())?;
        script::Loader::new(&first_lock_path).try_build()?
    };

    // generate the CID of the first lock script
    let cid_hash_codec = config.vlad_cid_hash_codec.unwrap_or(Codec::Sha3512);
    let cid = cid::Builder::new(Codec::Cidv1)
        .with_target_codec(Codec::Identity)
        .with_hash(
            &mh::Builder::new_from_bytes(cid_hash_codec, &first_lock_script)?.try_build()?
        )
        .try_build()?;

    // construct the signed vlad using the vlad pubkey and the first lock script cid
    let vlad = vlad::Builder::default()
        .with_signing_key(&vlad_mk)
        .with_cid(&cid)
        .try_build()?;

    // 2. Call back to get the entry and pub keys and load the lock and unlock scripts

    // get the codec for the entry signing key and get it
    let entrykey_codec = config.entrykey_codec.unwrap_or(Codec::Ed25519Priv);
    let entry_mk = get_key(OpenKey::EntryKey, entrykey_codec)?;

    // construct the initial pubkey for the plog
    let pubkey_codec = config.pubkey_codec.unwrap_or(Codec::Ed25519Priv);
    let pubkey_mk = get_key(OpenKey::PubKey, pubkey_codec)?;

    // load the entry lock script
    let lock_script = {
        let lock_path = config.entry_lock_script.ok_or::<Error>(OpenError::NoEntryLockScript.into())?;
        script::Loader::new(&lock_path).try_build()?
    };

    // load the entry unlock script
    let unlock_script = {
        let unlock_path = config.entry_unlock_script.ok_or::<Error>(OpenError::NoEntryUnlockScript.into())?;
        script::Loader::new(&unlock_path).try_build()?
    };

    // 3. Construct the three operations to advertise the keys

    // construct the Update("/entrykey") op to store the pubkey used for verifying the digital
    // signature over the first entry
    let entrykey_op = {
        let cv = entry_mk.conv_view()?;
        let entry_pk = cv.to_public_key()?;
        let entry_pk_data: Vec<u8> = entry_pk.into();
        op::Builder::new(OpId::Update)
            .with_key_path("/entrykey")
            .with_data_value(&entry_pk_data)
            .try_build()?
    };

    // construct the Update("/vladkey") op to store the pubkey used for verifying the digital
    // signature over the CID inside the VLAD.
    let vladkey_op = {
        let cv = vlad_mk.conv_view()?;
        let vlad_pk = cv.to_public_key()?;
        let vlad_pk_data: Vec<u8> = vlad_pk.into();
        op::Builder::new(OpId::Update)
            .with_key_path("/vladkey")
            .with_data_value(&vlad_pk_data)
            .try_build()?
    };

    // construct the Update("/pubkey") op to store the first advertised pubkey 
    let pubkey_op = {
        let cv = pubkey_mk.conv_view()?;
        let pubkey_pk = cv.to_public_key()?;
        let pubkey_pk_data: Vec<u8> = pubkey_pk.into();
        op::Builder::new(OpId::Update)
            .with_key_path("/pubkey")
            .with_data_value(&pubkey_pk_data)
            .try_build()?
    };

    // 4. Construct the first entry, calling back to get the entry signed

    // construct the first entry from all of the parts
    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .add_lock(&lock_script)
        .with_unlock(&unlock_script)
        .add_op(&entrykey_op)
        .add_op(&vladkey_op)
        .add_op(&pubkey_op)
        .try_build(|e| {
            // get the serialzied version of the entry with an empty "proof" field
            let ev: Vec<u8> = e.clone().into();
            // call the call back to have the caller sign the data
            let ms = sign_entry(&entry_mk, &ev)
                .map_err(|e| PlogError::from(EntryError::SignFailed(e.to_string())))?;
            // store the signature as proof
            Ok(ms.into())
        })?;

    // 5. Construct the log

    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock_script)
        .append_entry(&entry)
        .try_build()?;

    Ok(log)
}

