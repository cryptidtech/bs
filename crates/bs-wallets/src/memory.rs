//! Basic in-memory wallet implementation.
//! In memory Key manager and signer
use bs::config::sync::KeyPathProvider;
use bs::config::{Key, Multikey, Multisig};
use bs::ops::params::pubkey::PubkeyParams;
use bs::ops::params::vlad::VladParams;
pub use bs_traits::SyncGetKey;
use bs_traits::{GetKey, Signer, SyncSigner};
use multicodec::Codec;
use multikey::{mk, Views as _};
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

/// In-memory key manager that provides key management and signing capabilities.
///
/// You can specify an Error type that implements From<[multikey::Error]> and From<[multihash::Error]>
/// by using the turbo-fish operator `::<YourErrorType>`.
///
/// # Example
/// ```
/// use bs_wallets::memory::InMemoryKeyManager;
/// use bs::config::sync::KeyPathProvider;
/// use bs::config::sync::MultiSigner;
/// use bs::config::sync::KeyManager;
///
/// let key_manager = InMemoryKeyManager::default(); // same as InMemoryKeyManager::<bs::Error>::new();
/// test_default_error(key_manager);
///
/// // specify a custom error type, as long as it meets the bounds:
/// let key_manager = InMemoryKeyManager::<bs_peer::Error>::new();
///
/// // fixture
/// fn test_default_error<KP: KeyManager<bs::Error> + MultiSigner<bs::Error> + KeyPathProvider>(
///     _kp: KP,
/// ) {
/// }
#[derive(Debug)]
pub struct InMemoryKeyManager<E = bs::Error> {
    // Public keys for quick access
    vlad: Multikey,
    entry_key: Multikey,
    // Map of key paths to their corresponding secret keys
    secret_keys: Arc<Mutex<HashMap<String, Multikey>>>,
    _phantom: PhantomData<E>,
}

impl<E> Clone for InMemoryKeyManager<E> {
    fn clone(&self) -> Self {
        Self {
            vlad: self.vlad.clone(),
            entry_key: self.entry_key.clone(),
            secret_keys: self.secret_keys.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<E> Default for InMemoryKeyManager<E>
where
    E: From<multikey::Error> + From<multihash::Error> + Debug,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<E> KeyPathProvider for InMemoryKeyManager<E> {
    const VLAD_KEY_PATH: &'static str = VladParams::KEY_PATH;
    const PUBKEY_KEY_PATH: &'static str = PubkeyParams::KEY_PATH;
}

impl<E> InMemoryKeyManager<E>
where
    E: From<multikey::Error> + From<multihash::Error> + Debug,
{
    /// The default Codec
    pub(crate) const DEFAULT_CODEC: Codec = Codec::Ed25519Priv;

    /// Create a new key manager with auto-generated keys
    pub fn new() -> Self {
        // Generate random keys
        let vlad_secret =
            Self::generate_key(&Self::DEFAULT_CODEC).expect("Failed to generate vlad key");
        let entry_secret =
            Self::generate_key(&Self::DEFAULT_CODEC).expect("Failed to generate entry key");

        // Get public keys
        let vlad_public = vlad_secret
            .conv_view()
            .expect("Failed to convert vlad secret to view")
            .to_public_key()
            .expect("Failed to get vlad public key");
        let entry_public = entry_secret
            .conv_view()
            .expect("Failed to convert entry secret to view")
            .to_public_key()
            .expect("Failed to get entry public key");

        // Map of paths to secret keys
        let mut secret_keys = HashMap::new();
        secret_keys.insert(Self::VLAD_KEY_PATH.to_string(), vlad_secret);
        secret_keys.insert(Self::PUBKEY_KEY_PATH.to_string(), entry_secret);

        Self {
            vlad: vlad_public,
            entry_key: entry_public,
            secret_keys: Arc::new(Mutex::new(secret_keys)),
            _phantom: PhantomData,
        }
    }

    /// Create a key manager from an existing vlad key and a deterministic entry key
    pub fn from_vlad_and_seed(
        vlad_secret: &Multikey,
        entry_seed: &[u8],
        entry_codec: &Codec,
    ) -> Result<Self, E> {
        // Convert vlad to public key
        let vlad_public = vlad_secret.conv_view()?.to_public_key()?;

        // Generate entry key from seed
        let entry_secret = Self::generate_from_seed(entry_codec, entry_seed)?;
        let entry_public = entry_secret.conv_view()?.to_public_key()?;

        // Create the secret key map
        let mut secret_keys = HashMap::new();
        secret_keys.insert(Self::VLAD_KEY_PATH.to_string(), vlad_secret.clone());
        secret_keys.insert(Self::PUBKEY_KEY_PATH.to_string(), entry_secret);

        Ok(Self {
            vlad: vlad_public,
            entry_key: entry_public,
            secret_keys: Arc::new(Mutex::new(secret_keys)),
            _phantom: PhantomData,
        })
    }

    /// Returns the vlad key
    pub fn vlad(&self) -> &Multikey {
        &self.vlad
    }

    /// Returns the entry key
    pub fn entry_key(&self) -> &Multikey {
        &self.entry_key
    }

    /// Get public key by path - enhanced to support custom path lookups too
    fn get_public_key_by_path(&self, path: &str) -> Result<Option<Multikey>, E> {
        // Check standard paths first
        if path == Self::VLAD_KEY_PATH {
            return Ok(Some(self.vlad.clone()));
        }

        if path == Self::PUBKEY_KEY_PATH {
            return Ok(Some(self.entry_key.clone()));
        }

        // For custom paths, check if we have the secret key and convert to public
        let secret_keys = self.secret_keys.lock().unwrap();
        if let Some(secret_key) = secret_keys.get(path) {
            let public_key = secret_key.conv_view()?.to_public_key()?;
            return Ok(Some(public_key));
        }

        Ok(None)
    }

    /// Determine path from public key
    fn get_path_for_key(&self, key: &Multikey) -> Option<String> {
        if self.keys_match(key, &self.vlad) {
            Some(Self::VLAD_KEY_PATH.to_string())
        } else if self.keys_match(key, &self.entry_key) {
            Some(Self::PUBKEY_KEY_PATH.to_string())
        } else {
            // For keys not in our public set, we need to check against all stored keys
            if let Ok(secret_keys) = self.secret_keys.lock() {
                for (path, secret_key) in secret_keys.iter() {
                    if let Ok(public_key) =
                        secret_key.conv_view().and_then(|view| view.to_public_key())
                    {
                        if self.keys_match(key, &public_key) {
                            return Some(path.clone());
                        }
                    }
                }
            }
            None
        }
    }

    /// Get secret key by path
    fn get_secret_key(&self, path: &str) -> Result<Option<Multikey>, E> {
        let secret_keys = self.secret_keys.lock().unwrap();
        Ok(secret_keys.get(path).cloned())
    }

    /// Store secret key by path
    fn store_secret_key(&self, path: &str, secret_key: Multikey) -> Result<(), E> {
        let mut secret_keys = self.secret_keys.lock().unwrap();
        secret_keys.insert(path.to_string(), secret_key);
        Ok(())
    }

    /// Remove secret key by path
    fn remove_secret_key(&self, path: &str) -> Result<(), E> {
        let mut secret_keys = self.secret_keys.lock().unwrap();
        secret_keys.remove(path);
        Ok(())
    }

    /// Compare two key fingerprints
    fn keys_match(&self, key1: &Multikey, key2: &Multikey) -> bool {
        key1.eq(key2)
    }

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

    /// Remove the vlad secret key after use to enhance security
    pub fn cleanup_vlad_secret(&self) -> Result<(), E> {
        self.remove_secret_key(Self::VLAD_KEY_PATH)
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

        // Return the existing public key if we have it
        if let Some(key) = self.get_public_key_by_path(&path_str)? {
            tracing::debug!(
                "Returning existing key for path {}: {:?}",
                path_str,
                key.fingerprint_view()?.fingerprint(Codec::Sha2256)?
            );
            // log whether it's priv key or not using AttrView is_secret_key
            if key.attr_view()?.is_secret_key() {
                tracing::debug!("Key is a secret key");
            } else {
                tracing::debug!("Key is a public key");
            }

            return Ok(key);
        }

        // Generate a new key
        let secret_key = Self::generate_key(codec)?;
        tracing::debug!(
            "Generated new key for path {}: {:?}",
            path_str,
            secret_key.fingerprint_view()?.fingerprint(Codec::Sha2256)?
        );
        let public_key = secret_key.conv_view()?.to_public_key()?;

        // Store the secret key for future use
        self.store_secret_key(&path_str, secret_key)?;

        Ok(public_key)
    }
}

impl<E> Signer for InMemoryKeyManager<E>
where
    E: From<multikey::Error> + From<multihash::Error> + Debug,
{
    type Key = Multikey;
    type Signature = Multisig;
    type Error = E;
}

impl<E> SyncSigner for InMemoryKeyManager<E>
where
    E: From<multikey::Error> + From<multihash::Error> + From<multicid::Error> + Debug,
{
    fn try_sign(&self, key: &Self::Key, data: &[u8]) -> Result<Self::Signature, Self::Error> {
        tracing::trace!(
            "Signing request for data with key: {:?}, data length: {}",
            key.fingerprint_view()?.fingerprint(Codec::Sha2256)?,
            data.len()
        );
        // Get the key path from the key
        let key_path = self.get_path_for_key(key).ok_or(multikey::Error::Cipher(
            multikey::error::CipherError::InvalidKey,
        ))?;

        // Get the secret key corresponding to the provided path
        let secret_key = self
            .get_secret_key(&key_path)?
            .ok_or(multikey::Error::Cipher(
                multikey::error::CipherError::MissingKey,
            ))?;

        let msg = data;
        let combined = false;
        let scheme = None;

        let signmk = secret_key.sign_view()?;
        let signature = signmk.sign(msg, combined, scheme)?;

        let sig_bytes_raw: Vec<u8> = signature.clone().into();
        tracing::debug!(
            "try_sign Signature created with {} bytes, first 4 bytes: {:02x?} ({:?} dec)",
            sig_bytes_raw.len(),
            &sig_bytes_raw[..4],
            &sig_bytes_raw[..4]
        );

        // For vlad key, remove the secret after use for enhanced security
        if key_path == Self::VLAD_KEY_PATH {
            tracing::debug!("Cleaning up vlad secret key after signing");
            self.remove_secret_key(&key_path)?;
        }

        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bs::{
        config::sync::{KeyManager, KeyPathProvider, MultiSigner},
        params::{entry_key::EntryKeyParams, pubkey::PubkeyParams, vlad::VladParams},
    };
    use bs_peer::BsPeer;

    // test fixture that fixes the Error tpye to bs::Error
    fn test_default_error<KP: KeyManager<bs::Error> + MultiSigner<bs::Error> + KeyPathProvider>(
        _kp: KP,
    ) {
    }

    // can use default, Error is bs:Error
    #[test]
    fn test_default_key_manager() {
        // Create key manager with default error type
        let key_manager = InMemoryKeyManager::default();
        test_default_error(key_manager);
    }

    #[tokio::test]
    async fn test_in_memory_key_manager() {
        // Create key manager with auto-generated keys
        let key_manager = InMemoryKeyManager::<bs_peer::Error>::new();

        // Test signing with the vlad key
        let data = b"test data";
        let signature = key_manager.try_sign(key_manager.vlad(), data).unwrap();

        // Verify signature
        let verify_result = key_manager
            .vlad()
            .verify_view()
            .unwrap()
            .verify(&signature, Some(data));
        assert!(verify_result.is_ok());

        // Trying to sign again with vlad key should fail as it's cleaned up after use
        assert!(key_manager.try_sign(key_manager.vlad(), data).is_err());

        // But we can still sign with entry key
        let entry_signature = key_manager.try_sign(key_manager.entry_key(), data).unwrap();
        let entry_verify = key_manager
            .entry_key()
            .verify_view()
            .unwrap()
            .verify(&entry_signature, Some(data));
        assert!(entry_verify.is_ok());
    }

    #[tokio::test]
    async fn test_dynamic_key_generation() {
        // Create key manager
        let key_manager = InMemoryKeyManager::<bs_peer::Error>::new();

        // Request a key with a custom path
        let custom_path = Key::try_from("/custom/key/path").unwrap();
        let custom_key = key_manager
            .get_key(
                &custom_path,
                &InMemoryKeyManager::<bs_peer::Error>::DEFAULT_CODEC,
                1,
                1,
            )
            .unwrap();

        // Get the key again - should be the same one from storage
        let custom_key2 = key_manager
            .get_key(
                &custom_path,
                &InMemoryKeyManager::<bs_peer::Error>::DEFAULT_CODEC,
                1,
                1,
            )
            .unwrap();

        // Test that the keys we retrieved are identical
        assert!(
            key_manager.keys_match(&custom_key, &custom_key2),
            "The two retrieved keys should be identical"
        );

        // Try signing with the custom key
        let data = b"test custom key";
        let signature = key_manager.try_sign(&custom_key, data).unwrap();

        // Verify signature
        let verify_result = custom_key
            .verify_view()
            .unwrap()
            .verify(&signature, Some(data));
        assert!(
            verify_result.is_ok(),
            "Signature verification should succeed"
        );
    }

    #[tokio::test]
    async fn test_with_bs_peer() {
        // Create key manager
        let key_manager = InMemoryKeyManager::<bs_peer::Error>::new();

        // Create a BS peer with our key manager
        let _bs_peer = BsPeer::new(key_manager).await;
    }

    #[tokio::test]
    async fn test_cleanup_vlad_secret() {
        let key_manager = InMemoryKeyManager::<bs_peer::Error>::new();

        // Verify we can sign with vlad key initially
        let data = b"test data";
        let signature = key_manager.try_sign(key_manager.vlad(), data).unwrap();
        assert!(key_manager
            .vlad()
            .verify_view()
            .unwrap()
            .verify(&signature, Some(data))
            .is_ok());

        // After signing with vlad, the secret should be automatically removed
        assert!(key_manager.try_sign(key_manager.vlad(), data).is_err());

        // Manually clean up a secret key
        let key_manager = InMemoryKeyManager::<bs_peer::Error>::new();
        key_manager.cleanup_vlad_secret().unwrap();
        assert!(key_manager.try_sign(key_manager.vlad(), data).is_err());
    }
}
