//! Peer
use bs::{
    config::sync::{KeyManager, MultiSigner},
    error::{BsCompatibleError, OpenError},
};
use multicodec::Codec;
use multisig::Multisig;
use provenance_log as p;

use crate::{platform, Error};

/// A peer in the network
pub struct BsPeer {
    plog: Option<p::Log>,
    key_manager: Box<dyn KeyManager<Error>>,
    signer: Box<dyn MultiSigner<Error>>,
}

impl BsPeer {
    pub async fn new(
        key_manager: impl KeyManager<Error>,
        signer: impl MultiSigner<Error>,
    ) -> Result<Self, Error> {
        // Create the Peer
        let _blockstore = platform::Blockstore::new("bs-peer".into()).await?;
        Ok(BsPeer {
            key_manager: Box::new(key_manager),
            signer: Box::new(signer),
            plog: None,
        })
    }

    /// Create, uccess if plog is not already created
    pub async fn create(&mut self, codec: Codec, multisig: Multisig) -> Result<(), Error> {
        if self.plog.is_some() {
            return Err(Error::PlogAlreadyExists);
        }

        let config = bs::open::Config {
            vlad_params: None,
            entrykey_params: None,
            pubkey_params: None,
            entry_lock_script: None,
            entry_unlock_script: None,
            additional_ops: vec![],
        };

        let plog = bs::ops::open_plog(config, &*self.key_manager, &*self.signer)?;

        self.plog = Some(plog);
        Ok(())
    }
}
