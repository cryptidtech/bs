//! BetterSign Peer: BetterSign core + libp2p networking + Blockstore
use crate::{platform, Error};
use ::cid::Cid;
use blockstore::Blockstore as BlockstoreTrait;
use bs::{
    config::sync::{KeyManager, MultiSigner},
    params::{
        anykey::PubkeyParams,
        vlad::{FirstEntryKeyParams, VladParams},
    },
    update::OpParams,
};
use bs_traits::CondSync;
use multicid::cid;
use multicodec::Codec;
use multihash::mh;
use provenance_log::key::key_paths::ValidatedKeyParams;
use provenance_log::{self as p, Key, Script};

/// A peer in the network that is generic over the blockstore type
pub struct BsPeer<KP, BS>
where
    KP: KeyManager<Error> + MultiSigner<Error>,
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
    KP: KeyManager<Error> + MultiSigner<Error> + CondSync,
    BS: BlockstoreTrait + CondSync,
{
    /// Returns the p[p::Log] of the peer, if it exists.
    pub fn plog(&self) -> Option<&p::Log> {
        self.plog.as_ref()
    }

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
        tracing::debug!("Storing CIDs in blockstore... {:?}", ops);
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

    /// Store all the plog [provenance_log::Entry]s in the [blockstore::Blockstore]
    async fn store_entries(&self) -> Result<(), Error> {
        let plog = self.plog.as_ref().ok_or(Error::PlogNotInitialized)?;
        // add the first lock CID to the blockstore
        // first we need to convert from multicid::Cid to cid::Cid
        let first_lock_cid = plog.vlad.cid();
        let first_lock_cid_bytes: Vec<u8> = first_lock_cid.clone().into();
        let first_lock_cid = Cid::try_from(first_lock_cid_bytes.clone())?;

        // Next we need to extract the first lock script as Script
        let first_lock_bytes: Vec<u8> = plog.first_lock.clone().into();

        // the Cid of the extracted bytes should match those in the vlad.cid()
        let plog_vlad_cid_bytes: Vec<u8> = plog.vlad.cid().clone().into();
        debug_assert_eq!(first_lock_cid_bytes, plog_vlad_cid_bytes);

        self.blockstore
            .put_keyed(&first_lock_cid, &first_lock_bytes)
            .await?;

        // Put all the entries in the blockstore
        for (multi_cid, entry) in plog.entries.clone() {
            let entry_bytes: Vec<u8> = entry.into();

            // we need to convert multicid::Cid to cid:Cid first before putting it in the blockstore,
            // as the two are different types.
            let multi_cid_bytes: Vec<u8> = multi_cid.into();
            let cid = Cid::try_from(multi_cid_bytes)?;

            self.blockstore.put_keyed(&cid, &entry_bytes).await?;
        }

        Ok(())
    }

    /// Generate a new Plog with the given configuration.
    pub async fn generate_with_config(&mut self, config: bs::open::Config) -> Result<(), Error> {
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
        self.store_entries().await?;
        Ok(())
    }

    /// Generate a new Plog with the given lock and unlock scripts.
    pub async fn generate(
        &mut self,
        lock: impl AsRef<str>,
        unlock: impl AsRef<str>,
    ) -> Result<(), Error> {
        if self.plog.is_some() {
            return Err(Error::PlogAlreadyExists);
        }

        let config = bs::open::Config::builder()
            .vlad(VladParams::<FirstEntryKeyParams>::default())
            .pubkey(
                PubkeyParams::builder()
                    .codec(Codec::Ed25519Priv)
                    .build()
                    .into(),
            )
            .entrykey(
                FirstEntryKeyParams::builder()
                    .codec(Codec::Ed25519Priv)
                    .build()
                    .into(),
            )
            .lock(Script::Code(Key::default(), lock.as_ref().into()))
            .unlock(Script::Code(Key::default(), unlock.as_ref().into()))
            .additional_ops(vec![])
            .build();

        self.generate_with_config(config).await
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

    /// Load a Plog into ths BsPeer.
    pub async fn load(&mut self, plog: p::Log) -> Result<(), Error> {
        if self.plog.is_some() {
            return Err(Error::PlogAlreadyExists);
        }

        // Verify the plog
        {
            let verify_iter = &mut plog.verify();
            for result in verify_iter {
                if let Err(e) = result {
                    tracing::error!("Plog verification failed: {}", e);
                    return Err(Error::PlogVerificationFailed(e));
                }
            }
        }

        // Store the plog
        self.plog = Some(plog);
        self.store_entries().await?;
        Ok(())
    }
}

// directories for the platform-specific blockstore
#[cfg(target_arch = "wasm32")]
fn directories() -> String {
    // For wasm, we use a default directory
    "bs-peer".into()
}

#[cfg(not(target_arch = "wasm32"))]
fn directories() -> std::path::PathBuf {
    // For non-wasm, we use the platform-specific directories
    directories::ProjectDirs::from("tech", "cryptid", "BetterSignPeer")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| "bs-peer".into())
}

// Default implementation for platform-specific blockstore
impl<KP> DefaultBsPeer<KP>
where
    KP: KeyManager<Error> + MultiSigner<Error> + CondSync,
{
    /// Create a new Peer with the given key provider, opens
    /// a new platform-specific Blockstore for the Peer.
    pub async fn new(key_provider: KP) -> Result<Self, Error> {
        let directory = directories();
        let blockstore = platform::Blockstore::new(directory).await?;
        Ok(Self::with_blockstore(key_provider, blockstore))
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use crate::test_utils;
    use tracing_subscriber::fmt;

    #[allow(dead_code)]
    fn init_logger() {
        let subscriber = fmt().with_env_filter("bs_peer=trace").finish();
        if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
            tracing::warn!("failed to set subscriber: {}", e);
        }
    }

    #[tokio::test]
    async fn basic_test() {
        // init_logger();
        test_utils::run_basic_test().await;
    }

    #[tokio::test]
    async fn in_memory_blockstore_test() {
        // init_logger();
        test_utils::run_in_memory_blockstore_test().await;
    }

    #[tokio::test]
    async fn test_store_entries() {
        // init_logger();
        test_utils::run_store_entries_test().await;
    }

    #[tokio::test]
    async fn run_update_test() {
        // init_logger();
        test_utils::run_update_test().await;
    }

    #[tokio::test]
    async fn run_load_test() {
        // init_logger();
        test_utils::run_load_test().await;
    }
}
