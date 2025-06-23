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
pub use bs_p2p::events::api::Client;
pub use bs_p2p::events::PublicEvent;
use bs_traits::CondSync;
use futures::channel::mpsc::{self};
pub use libp2p::PeerId;
use multicid::cid;
use multicodec::Codec;
use multihash::mh;
use provenance_log::key::key_paths::ValidatedKeyParams;
pub use provenance_log::resolver::{ResolvedPlog, Resolver};
pub use provenance_log::{self as p, Key, Script};
use std::{future::Future, pin::Pin};

/// A peer that is generic over the blockstore type.
///
/// Can operate offline with just a local blockstore, or connect to a network
#[derive(Debug)]
pub struct BsPeer<KP, BS>
where
    KP: KeyManager<Error> + MultiSigner<Error>,
    BS: BlockstoreTrait + CondSync,
{
    /// The Provenance Log of the peer, which contains the history of operations
    plog: Option<p::Log>,
    /// Key provider for the peer, used for signing and key management
    key_provider: KP,
    /// [Blockstore] to save data
    blockstore: BS,
    /// Client handle to send commands to the network
    pub network_client: Option<Client>,
    /// Events emitted from the network
    pub events: Option<mpsc::Receiver<PublicEvent>>,
    /// The peer ID of this peer in the network
    pub peer_id: Option<PeerId>,
}

// Default platform-specific version of BsPeer
pub type DefaultBsPeer<KP> = BsPeer<KP, platform::Blockstore>;

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

impl<KP> DefaultBsPeer<KP>
where
    KP: KeyManager<Error> + MultiSigner<Error> + CondSync,
{
    /// Create a new [BsPeer] with the given key provider [KeyManager] and [MultiSigner],
    /// open a new platform-specific Blockstore,
    /// start a [bs_p2p] network node,
    /// set a network access [Client] to send commands,
    /// link an event receiver for network [bs_p2p::events::PublicEvent]s.
    pub async fn new(key_provider: KP) -> Result<Self, Error> {
        let blockstore = platform::Blockstore::new(directories()).await.unwrap();

        let (tx_evts, rx_evts) = mpsc::channel(16);
        let config = platform::StartConfig::default();
        let blockstore_clone = blockstore.clone();

        let (network_client, peer_id) = platform::start(tx_evts, blockstore_clone, config).await?;

        Ok(Self {
            network_client: Some(network_client),
            plog: None,
            key_provider,
            blockstore,
            events: Some(rx_evts),
            peer_id: Some(peer_id),
        })
    }
}

impl<KP, BS> BsPeer<KP, BS>
where
    KP: KeyManager<Error> + MultiSigner<Error> + CondSync,
    BS: BlockstoreTrait + CondSync,
{
    /// Returns the p[p::Log] of the peer, if it exists.
    pub fn plog(&self) -> Option<&p::Log> {
        self.plog.as_ref()
    }

    /// Create an offline (no network) [BsPeer] with a custom blockstore implementation
    pub fn with_blockstore(key_provider: KP, blockstore: BS) -> Self {
        Self {
            key_provider,
            plog: None,
            blockstore,
            network_client: Default::default(),
            events: None,
            peer_id: None,
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

                // get bytes back to verify
                let stored_data = self.blockstore.get(&cid).await?;
                if let Some(ref stored_data) = stored_data {
                    tracing::debug!("Stored data: {:?}", stored_data);
                } else {
                    tracing::error!("No data found for CID: {:?}", cid);
                }

                debug_assert!(stored_data.is_some(), "Data should be stored in blockstore");
                debug_assert_eq!(stored_data.unwrap(), data);
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

        tracing::debug!("Stored all Plog entries in blockstore");

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
        self.record_plog_to_dht().await?;
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
        let Some(ref mut plog) = self.plog else {
            return Err(Error::PlogNotInitialized);
        };

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

        // After successful update, store CIDs and publish DHT record
        self.store_ops(config.into()).await?;
        self.record_plog_to_dht().await?;

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

        // Store the plog, entries, and record to DHT
        self.plog = Some(plog);
        self.store_entries().await?;
        self.record_plog_to_dht().await?;

        Ok(())
    }

    /// Record Plog to DHT using Vlad as key and head CID as value
    async fn record_plog_to_dht(&self) -> Result<(), Error> {
        let Some(ref plog) = self.plog else {
            return Err(Error::PlogNotInitialized);
        };

        // Get Vlad bytes for DHT key
        let vlad_bytes: Vec<u8> = plog.vlad.cid().clone().into();

        // Get the head CID bytes for DHT value
        let head_cid_bytes: Vec<u8> = plog.head.clone().into();

        // Record to DHT if network client is available
        if let Some(client) = &self.network_client {
            tracing::debug!("Recording Plog to DHT with Vlad: {:?}", plog.vlad.cid());
            client.put_record(vlad_bytes, head_cid_bytes).await?;
            tracing::debug!("Successfully recorded Plog to DHT");
        } else {
            tracing::warn!("Network client not available, skipping DHT recording");
        }

        Ok(())
    }
}

impl<KP: KeyManager<Error> + MultiSigner<Error>> Resolver for &DefaultBsPeer<KP> {
    type Error = TestError;

    fn resolve(
        &self,
        cid: &multicid::Cid,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::Error>> + Send>> {
        tracing::debug!("DefaultBsPeer Resolving CID over bitswap: {}", cid);
        let cid_bytes: Vec<u8> = cid.clone().into();
        let client = self.network_client.clone();
        Box::pin(async move {
            let Some(client) = client else {
                return Err(TestError::NotConnected);
            };

            Ok(client.get_bits(cid_bytes).await?)
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum TestError {
    #[error("Provenance Log not initialized")]
    NotConnected,
    // from bs_p2p
    #[error("Plog already exists {0}")]
    P2p(#[from] bs_p2p::Error),
    // From<provenance_log::resolver::ResolveError>
    #[error("Resolve error {0}")]
    ResolveError(#[from] provenance_log::resolver::ResolveError),
    /// From<multicid::Error>
    #[error("Multicid error {0}")]
    MulticidError(#[from] multicid::Error),
    /// From<multihash::Error>
    #[error("Multihash error {0}")]
    MultihashError(#[from] multihash::Error),
    /// From<provenance_log::Error>
    #[error("Provenance Log error {0}")]
    PlogError(#[from] provenance_log::Error),
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use crate::utils;
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
        utils::run_basic_test().await;
    }

    #[tokio::test]
    async fn in_memory_blockstore_test() {
        // init_logger();
        utils::run_in_memory_blockstore_test().await;
    }

    #[tokio::test]
    async fn test_store_entries() {
        // init_logger();
        utils::run_store_entries_test().await;
    }

    #[tokio::test]
    async fn run_update_test() {
        // init_logger();
        utils::run_update_test().await;
    }

    #[tokio::test]
    async fn run_load_test() {
        // init_logger();
        utils::run_load_test().await;
    }

    #[tokio::test]
    async fn test_peer_initialization() {
        // init_logger();
        utils::run_peer_initialization_test().await;
    }
}
