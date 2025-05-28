//! Peer
use bs::config::sync::{KeyManager, MultiSigner};
use multicodec::Codec;
use multikey::Multikey;
use multisig::Multisig;
use provenance_log as p;

use crate::{platform, Error};

/// A peer in the network
pub struct BsPeer {
    key_manager: Box<dyn KeyManager>,
    signer: Box<dyn MultiSigner>,
}

impl BsPeer {
    pub async fn new(
        key_manager: impl KeyManager,
        signer: impl MultiSigner,
    ) -> Result<Self, Error> {
        // Create the Peer
        let _blockstore = platform::Blockstore::new("bs-peer".into()).await?;
        Ok(BsPeer {
            key_manager: Box::new(key_manager),
            signer: Box::new(signer),
        })
    }
}
