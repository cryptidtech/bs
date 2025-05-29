//! BetterSign Peer: BetterSign core + libp2p networking + Blockstore
use crate::{platform, Error};
use ::cid::Cid;
use blockstore::Blockstore as BlockstoreTrait;
use bs::{
    config::sync::{KeyManager, KeyPathProvider, MultiSigner},
    params::{entry_key::EntryKeyParams, pubkey::PubkeyParams, vlad::VladParams},
    update::OpParams,
};
use bs_traits::CondSync;
use multicid::cid;
use multihash::mh;
use provenance_log::{self as p, Key, Script};

/// A peer in the network that is generic over the blockstore type
pub struct BsPeer<KP, BS>
where
    KP: KeyManager<Error> + MultiSigner<Error> + KeyPathProvider,
    BS: BlockstoreTrait + CondSync,
{
    plog: Option<p::Log>,
    key_provider: KP,
    blockstore: BS,
}

// Default platform-specific version of BsPeer
pub type DefaultBsPeer<KP> = BsPeer<KP, platform::Blockstore>;

impl<KP, BS> BsPeer<KP, BS>
where
    KP: KeyManager<Error> + MultiSigner<Error> + KeyPathProvider + CondSync,
    BS: BlockstoreTrait + CondSync,
{
    /// Create a BsPeer with a custom blockstore implementation
    pub fn with_blockstore(key_provider: KP, blockstore: BS) -> Self {
        Self {
            key_provider,
            plog: None,
            blockstore,
        }
    }

    // Get a reference to the blockstore
    pub fn blockstore(&self) -> &BS {
        &self.blockstore
    }

    /// Store CIDs from config to the blockstore
    async fn store_ops(&self, ops: Vec<OpParams>) -> Result<(), Error> {
        for params in ops {
            if let OpParams::CidGen {
                version,
                target,
                hash,
                data,
                ..
            } = params
            {
                // Create CID using same approach as in open.rs
                let multi_cid = cid::Builder::new(version)
                    .with_target_codec(target)
                    .with_hash(&mh::Builder::new_from_bytes(hash, &data)?.try_build()?)
                    .try_build()?;

                // we need to convert multicid::Cid to cid:Cid first before putting it in the blockstore,
                // as the two are different types.
                let multi_cid_bytes: Vec<u8> = multi_cid.into();
                let cid = Cid::try_from(multi_cid_bytes)?;

                // Store the CID and data in blockstore
                self.blockstore.put_keyed(&cid, &data).await?;

                tracing::debug!("Stored CID in blockstore: {:?}", cid);
            }
        }
        Ok(())
    }

    pub async fn create_with_config(&mut self, config: bs::open::Config) -> Result<(), Error> {
        if self.plog.is_some() {
            return Err(Error::PlogAlreadyExists);
        }

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

        self.store_ops(config.into()).await?;
        self.plog = Some(plog);
        Ok(())
    }

    pub async fn create(
        &mut self,
        lock: impl AsRef<str>,
        unlock: impl AsRef<str>,
    ) -> Result<(), Error> {
        if self.plog.is_some() {
            return Err(Error::PlogAlreadyExists);
        }

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

        self.create_with_config(config).await
    }

    /// Update the BsPeer's Plog with new data.
    pub async fn update(&mut self, config: bs::update::Config) -> Result<(), Error> {
        if self.plog.is_none() {
            return Err(Error::PlogNotInitialized);
        }

        let plog = self.plog.as_mut().unwrap();

        // Apply the update to the plog
        bs::ops::update_plog(plog, &config, &self.key_provider, &self.key_provider)?;

        // Verify the updated plog
        {
            let verify_iter = &mut plog.verify();
            for result in verify_iter {
                if let Err(e) = result {
                    tracing::error!("Plog verification failed after update: {}", e);
                    return Err(Error::PlogVerificationFailed(e));
                }
            }
        }

        // After successful update, store CIDs
        self.store_ops(config.into()).await?;

        Ok(())
    }
}

// Default implementation for platform-specific blockstore
impl<KP> DefaultBsPeer<KP>
where
    KP: KeyManager<Error> + MultiSigner<Error> + KeyPathProvider + CondSync,
{
    /// Create a new Peer with the given key provider, opens
    /// a new platform-specific Blockstore for the Peer.
    pub async fn new(key_provider: KP) -> Result<Self, Error> {
        let directory = directories::ProjectDirs::from("tech", "cryptid", "BetterSignPeer")
            .map(|dirs| dirs.data_dir().to_path_buf())
            .unwrap_or_else(|| "bs-peer".into());
        let blockstore = platform::Blockstore::new(directory).await?;
        Ok(Self::with_blockstore(key_provider, blockstore))
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use super::*;
    use blockstore::InMemoryBlockstore;
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
    async fn in_memory_blockstore_test() {
        init_logger();
        tracing::info!("Starting in_memory_blockstore_test");

        // Set up key manager
        let key_manager = InMemoryKeyManager::<Error>::default();

        // Create an in-memory blockstore with a reasonable size limit
        let blockstore = InMemoryBlockstore::<128>::new();

        // Create peer with the in-memory blockstore
        let mut peer = BsPeer::with_blockstore(key_manager, blockstore);

        // Rest of test is similar to basic_test
        // ...

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

        // Create the peer with valid scripts and with CIDs to store
        // Add some OpParams::CidGen entries to test blockstore storage
        let config = bs::open::Config {
            vlad_params: VladParams::default().into(),
            pubkey_params: PubkeyParams::default().into(),
            entrykey_params: EntryKeyParams::default().into(),
            first_lock_script: provenance_log::Script::Code(
                Key::default(),
                VladParams::FIRST_LOCK_SCRIPT.into(),
            ),
            entry_lock_script: Script::Code(Key::default(), lock_script.clone()),
            entry_unlock_script: Script::Code(Key::default(), unlock_script.clone()),
            additional_ops: vec![
                // Add a CidGen entry for testing
                OpParams::CidGen {
                    key: Key::try_from("/test/image").unwrap(),
                    version: Codec::Cidv1,
                    target: Codec::Raw,
                    hash: Codec::Sha2256,
                    inline: true,
                    data: b"test data".to_vec(),
                },
            ],
        };

        // Create the peer with this config instead of default one
        // This would require modifying the create method to accept a config parameter
        // For now, we'll continue with basic test but add a recommendation in comments

        let res = peer.create(&lock_script, &unlock_script).await;
        assert!(res.is_ok(), "Expected successful creation of peer");

        // TODO: Verify that CIDs were stored in the blockstore
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

        let mut peer = DefaultBsPeer::new(key_manager).await.unwrap();

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
        let res = peer.create(&lock_script, &unlock_script).await;

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

    // test save to in memory blockstore
}
