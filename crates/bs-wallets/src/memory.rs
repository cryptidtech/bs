//! Basic in-memory wallet implementation.
//! In memory Key manager and signer
use bs::config::{Key, Multikey, Multisig};
use bs::ops::params::pubkey::PubkeyParams;
use bs::ops::params::vlad::VladParams;
use bs_traits::{GetKey, Signer, SyncGetKey, SyncSigner};
use multibase::Base;
use multicodec::Codec;
use multihash::EncodedMultihash;
use multikey::{mk, Views as _};
use std::fmt::Debug;
use std::marker::PhantomData;

#[derive(Debug)]
pub struct InMemoryKeyManager<E = bs::Error> {
    vlad: Option<Multikey>,
    entry_key: Option<Multikey>,
    _phantom: PhantomData<E>,
}

impl<E> Clone for InMemoryKeyManager<E> {
    fn clone(&self) -> Self {
        Self {
            vlad: self.vlad.clone(),
            entry_key: self.entry_key.clone(),
            _phantom: PhantomData,
        }
    }
}
// Default implementation only for bs::Error since we need Debug to implement Default
impl Default for InMemoryKeyManager<bs::Error> {
    fn default() -> Self {
        Self {
            vlad: None,
            entry_key: None,
            _phantom: PhantomData,
        }
    }
}

// Separate impl block for methods that don't depend on E
impl<E> InMemoryKeyManager<E> {
    /// [Codec] for fingerprint
    pub(crate) const FINGERPRINT_CODEC: Codec = Codec::Sha3256;
    /// [Base] encoding for the fingerprint
    pub(crate) const FINGERPRINT_BASE: Base = Base::Base36Lower;
    /// Key path for the vlad key
    pub const VLAD_KEY_PATH: &'static str = VladParams::KEY_PATH;
    /// Key path for the public key
    pub const PUBKEY_KEY_PATH: &'static str = PubkeyParams::KEY_PATH;

    /// Create a new empty key manager
    pub fn new() -> Self {
        Self {
            vlad: None,
            entry_key: None,
            _phantom: PhantomData,
        }
    }

    /// Try to get an existing key, or None if not found
    pub fn get_existing_key(&self, key_path: &str) -> Option<Multikey> {
        match key_path {
            path if path == Self::VLAD_KEY_PATH => self.vlad.clone(),
            path if path == Self::PUBKEY_KEY_PATH => self.entry_key.clone(),
            _ => None,
        }
    }

    /// Returns the vlad key if it exists
    pub fn vlad(&self) -> Option<&Multikey> {
        self.vlad.as_ref()
    }

    /// Returns the entry key if it exists
    pub fn entry_key(&self) -> Option<&Multikey> {
        self.entry_key.as_ref()
    }
}

// Implementation for methods that require E to implement specific traits
impl<E> InMemoryKeyManager<E>
where
    E: From<multikey::Error> + From<multihash::Error> + Debug,
{
    /// Generate a new key for the given codec
    pub fn generate_key(codec: &Codec) -> Result<Multikey, E> {
        let mut rng = rand_core_6::OsRng;
        Ok(mk::Builder::new_from_random_bytes(*codec, &mut rng)?.try_build()?)
    }

    /// Generates from seed
    pub fn generate_from_seed(codec: &Codec, seed: &[u8]) -> Result<Multikey, E> {
        let mk = mk::Builder::new_from_seed(*codec, seed)?.try_build()?;
        Ok(mk)
    }

    /// Store a key for a specific path
    pub fn store_key(&mut self, key_path: &str, mk: &Multikey) -> Result<(), E> {
        match key_path {
            path if path == Self::VLAD_KEY_PATH => {
                // save the public multikey for the vlad
                tracing::trace!(
                    "[STORE] {}",
                    Self::encode(mk).expect("Failed to encode generated MK")
                );

                self.vlad = Some(mk.conv_view()?.to_public_key()?);
                tracing::trace!("Vlad key: {:#?}", self.vlad());
            }
            path if path == Self::PUBKEY_KEY_PATH => {
                self.entry_key = Some(mk.clone());
            }
            _ => {} // No storage for other keys
        }

        Ok(())
    }

    /// Encodes the Multikey to a string representation.
    fn encode(mk: &Multikey) -> Result<String, E> {
        let fp = mk
            .fingerprint_view()?
            .fingerprint(Self::FINGERPRINT_CODEC)?;
        let ef = EncodedMultihash::new(Self::FINGERPRINT_BASE, fp);
        Ok(ef.to_string())
    }
}

impl<E> GetKey for InMemoryKeyManager<E>
where
    E: From<multikey::Error> + From<multihash::Error> + Debug,
{
    type KeyPath = Key;
    type Codec = Codec;
    type Key = Multikey;
    type Error = E;
}

impl<E> SyncGetKey for InMemoryKeyManager<E>
where
    E: From<multikey::Error> + From<multihash::Error> + Debug,
{
    fn get_key<'a>(
        &'a self,
        key_path: &'a Self::KeyPath,
        codec: &'a Self::Codec,
        _threshold: usize,
        _limit: usize,
    ) -> Result<Self::Key, Self::Error> {
        let path_str = key_path.to_string();
        tracing::trace!("Key request for {}", path_str);

        // First try to get an existing key
        if let Some(key) = self.get_existing_key(&path_str) {
            return Ok(key);
        }

        // If we don't have a key, generate a new one
        // This key won't be stored internally, but the caller can store it if needed
        let new_key = Self::generate_key(codec)?;

        // Return the generated key
        Ok(new_key)
    }
}

impl<E> Signer for InMemoryKeyManager<E>
where
    E: From<multikey::Error> + Debug,
{
    type Key = Multikey;
    type Signature = Multisig;
    type Error = E;
}

impl<E> SyncSigner for InMemoryKeyManager<E>
where
    E: From<multikey::Error> + Debug,
{
    fn try_sign(&self, key: &Self::Key, data: &[u8]) -> Result<Self::Signature, Self::Error> {
        let msg = data;
        let combined = false;
        let scheme = None;
        Ok(key.sign_view()?.sign(msg, combined, scheme)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bs_peer::BsPeer;

    #[tokio::test]
    async fn test_in_memory_key_manager() {
        // Use bs_peer::Error as the error type for the test
        let key_manager = InMemoryKeyManager::<bs_peer::Error>::new();
        assert!(key_manager.vlad.is_none());
        assert!(key_manager.entry_key.is_none());

        let _bs_peer = BsPeer::new(key_manager.clone(), key_manager).await;
    }
}
