//! Peer
use bs::{
    config::sync::{KeyManager, KeyPathProvider, MultiSigner},
    params::{entry_key::EntryKeyParams, pubkey::PubkeyParams, vlad::VladParams},
};
use provenance_log::{self as p, Key, Script};

use crate::{platform, Error};

/// A peer in the network
pub struct BsPeer<KP: KeyManager<Error> + MultiSigner<Error> + KeyPathProvider> {
    plog: Option<p::Log>,
    key_provider: KP,
}

impl<KP> BsPeer<KP>
where
    KP: KeyManager<Error> + MultiSigner<Error> + KeyPathProvider,
{
    pub async fn new(key_provider: KP) -> Result<Self, Error> {
        // Create the Peer
        let _blockstore = platform::Blockstore::new("bs-peer".into()).await?;
        Ok(BsPeer {
            key_provider,
            plog: None,
        })
    }

    pub fn create(&mut self, lock: impl AsRef<str>, unlock: impl AsRef<str>) -> Result<(), Error> {
        if self.plog.is_some() {
            return Err(Error::PlogAlreadyExists);
        }

        // TODO: This is a bit awkward how the keys and the config are separate. Should we
        // colocate them somehow?
        // TODO: T::default().into() would be better
        let config = bs::open::Config {
            vlad_params: VladParams::default().into(),
            pubkey_params: PubkeyParams::default().into(),
            entrykey_params: EntryKeyParams::default().into(),
            first_lock_script: provenance_log::Script::Code(
                Key::default(),
                VladParams::FIRST_LOCK_SCRIPT.into(),
            ),
            entry_lock_script: Script::Code(Key::default(), lock.as_ref().into()),
            entry_unlock_script: Script::Code(Key::default(), unlock.as_ref().into()),
            additional_ops: vec![],
        };

        tracing::info!("Creating Plog with config: {:?}", config);

        // Pass the key_provider directly as both key_manager and signer
        let plog = bs::ops::open_plog(&config, &self.key_provider, &self.key_provider)?;
        {
            let verify_iter = &mut plog.verify();

            for result in verify_iter {
                if let Err(e) = result {
                    tracing::error!("Plog verification failed: {}", e);
                    return Err(Error::PlogVerificationFailed(e));
                }
            }
        }
        tracing::info!("Plog verification successful");

        self.plog = Some(plog);
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use super::*;
    use bs_wallets::memory::InMemoryKeyManager;
    use multicodec::Codec;
    use multikey::mk;
    use provenance_log::entry::Field;
    use tracing_subscriber::fmt;

    fn init_logger() {
        let subscriber = fmt().with_env_filter("bs_peer=trace").finish();
        if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
            tracing::warn!("failed to set subscriber: {}", e);
        }
    }

    #[tokio::test]
    async fn basic_test() {
        init_logger();
        tracing::info!("Starting basic_test");
        tracing::debug!("Initializing key manager and peer");
        // We create a Plog and Vlad and save the data to the Browser Blockstore
        // To create a new Peer, we call default() to get default values.
        let seed: [u8; 32] = [42; 32];
        let codec = Codec::Ed25519Priv;
        let _mk = mk::Builder::new_from_seed(codec, &seed)
            .unwrap()
            .try_build()
            .unwrap();

        let key_manager = InMemoryKeyManager::<Error>::default();

        let mut peer = BsPeer::new(key_manager).await.unwrap();

        let entry_key = Field::ENTRY;
        let proof_key = Field::PROOF;
        let pubkey = PubkeyParams::KEY_PATH;

        let unlock_script = format!(
            r#"
             // push the serialized Entry as the message
             push("{entry_key}");

             // push the proof data
             push("{proof_key}");
        "#
        );

        let lock_script = format!(
            r#"
                // then check a possible threshold sig...
                check_signature("/recoverykey", "{entry_key}") ||

                // then check a possible pubkey sig...
                check_signature("{pubkey}", "{entry_key}") ||
                
                // then the pre-image proof...
                check_preimage("/hash")
            "#
        );

        // Now we create the peer with valid scripts
        let res = peer.create(&lock_script, &unlock_script);

        // Check if the creation was successful
        assert!(res.is_ok(), "Expected successful creation of peer");
        tracing::info!("Peer created successfully");
        // Check if the plog is initialized
        assert!(peer.plog.is_some(), "Expected plog to be initialized");
        tracing::info!("Plog initialized successfully");

        // Check if the plog can be verified
        let plog = peer.plog.as_ref().unwrap();
        let verify_iter = &mut plog.verify();
        for result in verify_iter {
            if let Err(e) = result {
                tracing::error!("Plog verification failed: {}", e);
                panic!("Plog verification failed: {}", e);
            }
        }

        tracing::info!("Plog verification successful");
    }
}
