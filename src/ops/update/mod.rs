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

use crate::Error;
use provenance_log::{Entry, Log};

/// update a provenance log given the update config
pub fn update_plog(_log: &mut Log, _config: Config) -> Result<Entry, Error> {
    Ok(Entry::default())

    /*
    // get the coded for the ephemeral and first entry signing keys
    let ephemeral_codec = config.ephemeral_codec.unwrap_or(Codec::Ed25519Priv);

    // build the vlad key
    let mut rng = rand::rngs::OsRng::default();
    let vlad_mk = multikey::Builder::new_from_random_bytes(ephemeral_codec, &mut rng).try_build()?;

    // generate a speparate entry key if we're using Lamport signatures
    let entry_mk = if LAMPORT_CODECS.contains(ephemeral_codec) {
        multikey::Builder::new_from_random_bytes(ephemeral_codec, &mut rng).try_build()?
    } else {
        vlad_mk.clone()
    }

    // load the first lock script
    let first_lock_script = {
        let first_lock_path = config.first_lock_script.ok_or(OpenError::NoFirstLockScript.into())?;
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
        .with_cid(&first_lock_cid)
        .try_build();

    // construct the initial pubkey for the plog
    let entry_pubkey_codec = config.entry_pubkey_codec.unwrap_or(Codec::Ed25519Priv);
    let entry_pubkey_mk = multikey::Builder::new_from_random_bytes(entry_pubkey_codec, &mut rng).try_build()?;

    // TODO store the secret key in our local keychain

    // load the entry lock script
    let lock_script = {
        let lock_path = config.entry_lock_script.ok_or(OpenError::NoEntryLockScript.into())?;
        script::Loader::new(&lock_path).try_build()?
    };

    // load the entry unlock script
    let unlock_script = {
        let unlock_path = config.entry_unlock_script.ok_or(OpenError::NoEntryUnlockScript.into())?;
        script::Loader::new(&unlock_path).try_build()?
    };

    // construct the Update("/ephemeralkey") op to store the pubkey used for verifying the digital
    // signature over the first entry
    let ephemeralkey_op = {
        let cv = entry_mk.conv_view()?;
        let entry_pk = cv.to_public_key()?;
        let entry_pk_data: Vec<u8> = entry_pk.into();
        op::Builder::new(OpId::Update)
            .with_key_path("/ephemeralkey")
            .with_data_value(&entry_pk_data)
            .try_build()?
    };

    // construct the Update("/vladkey") op to store the pubkey used for verifying the digital
    // signature over the CID inside the VLAD. this pubkey will be the same as the `/ephmeralkey`
    // in all cases except when Lamport signatures are used to sign the VLAD and first entry
    let vladkey_op = {
        let cv = vlad_mk.conv_view()?;
        let vlad_pk = cv.to_public_key()?;
        let vlad_pk_data: Vec<u8> = vlad_pk.into();
        op::Builder::new(OpId::Update)
            .with_key_path("/vladkey")
            .with_data_value(&vlad_pk_data)
            .try_build()?
    }

    // construct the Update("/pubkey") op to store the first advertised pubkey 
    let pubkey_op = {
        let cv = entry_pubkey_mk.conv_view()?;
        let entry_pubkey_pk = cv.to_public_key()?;
        let entry_pubkey_pk_data: Vec<u8> = entry_pubkey_pk.into();
        op::Builder::new(OpId::Update)
            .with_key_path("/pubkey")
            .with_data_value(&entry_pubkey_pk_data)
            .try_build()?
    }

    // construct the first entry from all of the parts
    let entry = entry::Builder::default()
        .with_vlad(&vlad)
        .add_lock(&lock_script)
        .with_unlock(&unlock_script)
        .add_op(&ephemeralkey_op)
        .add_op(&vladkey_op)
        .add_op(&pubkey_op)
        .try_build(|e| {
            // this callback is for constructing the "proof" field value

            // get the serialzied version of the entry with an empty "proof" field
            let ev: Vec<u8> = e.clone().into();
            // get the signing view on the entry_mk
            let sv = entry_mk.sign_view()?;
            // generate the signature over the event
            let ms = sv.sign(&ev, false, None)?;
            // store the signature as proof
            e.proof = ms.into();
            Ok(())
        })?

    let log = log::Builder::new()
        .with_vlad(&vlad)
        .with_first_lock(&first_lock_script)
        .append_entry(&entry)
        .try_build()?;

    //TODO store the plog in the local content addressable storage and set up the VLAD->CID and
    // pubkey to CID mappings.
    
    Ok(log)
    */
}


