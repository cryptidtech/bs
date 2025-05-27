//! Peer
use crate::{platform, Error};
use bs_traits::{AsyncGetKey, AsyncSigner, GetKey, Signer};

pub mod p {
    pub use multicodec::Codec;
    pub use multikey::{Multikey, Views};
    pub use multisig::Multisig;
    pub use provenance_log::{
        entry, error::EntryError, Error as PlogError, Key, Log, OpId, Script,
    };
}

pub trait KeyGetterTrait:
    GetKey<KeyPath = p::Key, Codec = p::Codec, Key = p::Multikey, Error = Error>
    + AsyncGetKey
    + Send
    + Sync
    + 'static
{
}

pub trait SignerTrait:
    Signer<Key = p::Multikey, Signature = p::Multisig, Error = Error>
    + AsyncSigner
    + Send
    + Sync
    + 'static
{
}

impl<T> KeyGetterTrait for T where
    T: GetKey<KeyPath = p::Key, Codec = p::Codec, Key = p::Multikey, Error = Error>
        + AsyncGetKey
        + Send
        + Sync
        + 'static
{
}

impl<T> SignerTrait for T where
    T: Signer<Key = p::Multikey, Signature = p::Multisig, Error = Error>
        + AsyncSigner
        + Send
        + Sync
        + 'static
{
}

// Create simple type aliases
pub type KeyGetter = dyn KeyGetterTrait;
pub type BsSigner = dyn SignerTrait;

/// A peer in the network
pub struct BsPeer {
    key_manager: Box<KeyGetter>,
    signer: Box<BsSigner>,
}

impl BsPeer {
    pub async fn new(
        key_manager: impl KeyGetterTrait,
        signer: impl SignerTrait,
    ) -> Result<Self, Error> {
        // Create the Peer
        let _blockstore = platform::Blockstore::new("bs-peer".into()).await?;
        Ok(BsPeer {
            key_manager: Box::new(key_manager),
            signer: Box::new(signer),
        })
    }

    // Async methods using our traits
    pub async fn get_key(&self, path: &p::Key) -> Result<p::Multikey, Error> {
        self.key_manager
            .get_key(path, &p::Codec::default(), 1, 1)
            .await
    }

    pub async fn sign(&self, key: &p::Multikey, data: &[u8]) -> Result<p::Multisig, Error> {
        self.signer.try_sign(key, data).await
    }

    // Convenience method that doesn't require passing the key
    pub async fn sign_with_default_key(&self, data: &[u8]) -> Result<p::Multisig, Error> {
        // Get the default key (you might want to cache this)
        let default_key_path = p::Key::default(); // Assuming there's a sensible default
        let key = self.get_key(&default_key_path).await?;
        self.sign(&key, data).await
    }
}
