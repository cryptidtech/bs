//! Basic in-memory wallet implementation.
//! In memory Key manager and [Signer]
pub use bs_traits::sync::{
    EphemeralSigningTuple, SyncGetKey, SyncPrepareEphemeralSigning, SyncSigner,
};
use bs_traits::{EphemeralKey, GetKey, Signer};
use multicodec::Codec;
use multikey::{mk, Multikey, Views as _};
use multisig::Multisig;
use provenance_log::Key;
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
/// In-memory key manager that provides key management and signing capabilities.
///
/// You can specify an Error type that implements From<[multikey::Error]> and From<[multihash::Error]>
/// by using the turbo-fish operator `::<YourErrorType>`.
///
/// # Example
/// ```
/// use bs_wallets::memory::InMemoryKeyManager;
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
/// fn test_default_error<KP: KeyManager<bs::Error> + MultiSigner<bs::Error>>(
///     _kp: KP,
/// ) {
/// }
#[derive(Debug)]
pub struct InMemoryKeyManager<E = crate::Error> {
    // Map of key paths to their corresponding secret keys
    secret_keys: Arc<Mutex<HashMap<Key, Multikey>>>,
    _phantom: PhantomData<E>,
}

impl<E> Clone for InMemoryKeyManager<E> {
    fn clone(&self) -> Self {
        Self {
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

impl<E> InMemoryKeyManager<E>
where
    E: From<multikey::Error> + From<multihash::Error> + Debug,
{
    /// Create a new key manager with auto-generated keys
    pub fn new() -> Self {
        Self {
            secret_keys: Arc::new(Mutex::new(HashMap::new())),
            _phantom: PhantomData,
        }
    }

    /// Get public key by path - enhanced to support custom path lookups too
    fn get_public_key_by_path(&self, path: &Key) -> Result<Option<Multikey>, E> {
        // For custom paths, check if we have the secret key and convert to public
        let secret_keys = self.secret_keys.lock().unwrap();
        if let Some(secret_key) = secret_keys.get(path) {
            let public_key = secret_key.conv_view()?.to_public_key()?;
            return Ok(Some(public_key));
        }

        Ok(None)
    }

    /// Get secret key by path
    fn get_secret_key(&self, path: &Key) -> Result<Option<Multikey>, E> {
        let secret_keys = self.secret_keys.lock().unwrap();
        Ok(secret_keys.get(path).cloned())
    }

    /// Store secret key by path
    pub fn store_secret_key(&self, path: Key, secret_key: Multikey) -> Result<(), E> {
        let mut secret_keys = self.secret_keys.lock().unwrap();
        secret_keys.insert(path, secret_key);
        Ok(())
    }

    /// Remove secret key by path
    pub fn remove_secret_key(&self, path: &Key) -> Result<(), E> {
        let mut secret_keys = self.secret_keys.lock().unwrap();
        secret_keys.remove(path);
        Ok(())
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
    /// Gets a key for the given path and codec, generating it if necessary under the specified threshold and limit.
    /// Saves the secret key for future use under the KeyPath provided.
    fn get_key<'a>(
        &'a self,
        key_path: &'a Self::KeyPath,
        codec: &'a Self::Codec,
        _threshold: NonZeroUsize,
        _limit: NonZeroUsize,
    ) -> Result<Self::Key, Self::Error> {
        tracing::trace!("Key request for {}", key_path);

        // Return the existing public key if we have it
        if let Some(key) = self.get_public_key_by_path(key_path)? {
            tracing::debug!(
                "Returning existing key for path {}: {:?}",
                key_path,
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
            key_path,
            secret_key.fingerprint_view()?.fingerprint(Codec::Sha2256)?
        );
        let public_key = secret_key.conv_view()?.to_public_key()?;

        // Store the secret key for future use
        self.store_secret_key(key_path.clone(), secret_key)?;

        Ok(public_key)
    }
}

impl<E> Signer for InMemoryKeyManager<E>
where
    E: From<multikey::Error> + From<multihash::Error> + Debug,
{
    type KeyPath = Key;
    type Signature = Multisig;
    type Error = E;
}

impl<E> EphemeralKey for InMemoryKeyManager<E>
where
    E: From<multikey::Error> + From<multihash::Error> + Debug,
{
    type PubKey = Multikey;
}

impl<E> SyncSigner for InMemoryKeyManager<E>
where
    E: From<multikey::Error>
        + From<multihash::Error>
        + From<multicid::Error>
        + From<crate::Error>
        + Debug,
{
    fn try_sign(
        &self,
        key_path: &Self::KeyPath,
        data: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        // Get the secret key corresponding to the provided path
        let secret_key = self
            .get_secret_key(key_path)?
            .ok_or(crate::Error::NoKeyPresent(key_path.clone()))?;

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

        Ok(signature)
    }
}

impl<E> SyncPrepareEphemeralSigning for InMemoryKeyManager<E>
where
    E: From<multikey::Error>
        + From<multihash::Error>
        + From<multicid::Error>
        + From<crate::Error>
        + Debug
        + 'static,
{
    type Codec = Codec; // multicodec::Codec

    fn prepare_ephemeral_signing(
        &self,
        codec: &Self::Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> EphemeralSigningTuple<
        <Self as EphemeralKey>::PubKey,
        <Self as Signer>::Signature,
        <Self as Signer>::Error,
    > {
        let mut rng = rand_core_6::OsRng;

        // Generate the secret key
        let secret_key = multikey::Builder::new_from_random_bytes(*codec, &mut rng)?
            .with_threshold(threshold)
            .with_limit(limit)
            .try_build()?;

        // Get the public key
        let public_key = secret_key.conv_view()?.to_public_key()?;

        // Create a FnOnce closure that owns the secret key and will be destroyed after use (on drop)
        let sign_once = Box::new(
            move |data: &[u8]| -> Result<<Self as Signer>::Signature, <Self as Signer>::Error> {
                let signature = secret_key.sign_view()?.sign(data, false, None)?;
                Ok(signature)
            },
        );

        Ok((public_key, sign_once))
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use super::*;
    use bs::config::sync::{KeyManager, MultiSigner};
    use bs_traits::sync::SyncSigner;
    use provenance_log::key::key_paths::ValidatedKeyParams;
    use tracing_subscriber::fmt;

    fn init_logger() {
        let subscriber = fmt().with_env_filter("trace").finish();
        if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
            tracing::warn!("failed to set subscriber: {}", e);
        }
    }

    // test fixture that fixes the Error tpye to bs::Error
    fn test_default_error<KP: KeyManager<crate::Error> + MultiSigner<crate::Error>>(_kp: KP) {}

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
        let key_manager = InMemoryKeyManager::<crate::Error>::new();

        // Test a regular non-ephemeral key
        let key_path = Key::try_from("/non/ephermal/key/path").unwrap();
        let test_mk =
            multikey::Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rand_core_6::OsRng)
                .unwrap()
                .try_build()
                .unwrap();

        // add to Wallet
        key_manager
            .store_secret_key(key_path.clone(), test_mk.clone())
            .unwrap();

        // can sign with stored key
        let data = b"test data";
        let signature = key_manager.try_sign(&key_path, data).unwrap();
        let verify_result = test_mk
            .verify_view()
            .unwrap()
            .verify(&signature, Some(data));
        assert!(verify_result.is_ok());
    }

    #[tokio::test]
    async fn test_dynamic_key_generation() {
        // Create key manager
        let key_manager = InMemoryKeyManager::<crate::Error>::new();

        // Request a key with a custom path
        let custom_path = Key::try_from("/custom/key/path").unwrap();

        // First call to get_key generates a key pair and stores the secret key,
        // but returns the public key
        let public_key = key_manager
            .get_key(
                &custom_path,
                &Codec::Ed25519Priv,
                NonZero::new(1).unwrap(),
                NonZero::new(1).unwrap(),
            )
            .unwrap();

        // Verify we got a public key
        assert!(public_key.attr_view().unwrap().is_public_key());

        // Get the key again - should be the same public key
        let public_key2 = key_manager
            .get_key(
                &custom_path,
                &Codec::Ed25519Priv,
                NonZero::new(1).unwrap(),
                NonZero::new(1).unwrap(),
            )
            .unwrap();

        assert!(
            public_key.eq(&public_key2),
            "The two retrieved public keys should be equal"
        );

        // Try signing with the key at the custom path
        // This works because the secret key is stored internally in the key manager
        let data = b"test custom key";
        let signature = key_manager.try_sign(&custom_path, data).unwrap();

        // Verify signature with the public key we have
        let verify_result = public_key
            .verify_view()
            .unwrap()
            .verify(&signature, Some(data));
        assert!(
            verify_result.is_ok(),
            "Signature verification should succeed"
        );
    }

    #[tokio::test]
    async fn test_prepare_ephemeral_signing() {
        init_logger();

        tracing::info!("Starting test_prepare_ephemeral_signing");

        let key_manager = InMemoryKeyManager::<crate::Error>::new();
        let data = b"test ephemeral signing";

        // Use prepare_ephemeral_signing to get a public key and a one-time signing function
        let (public_key, sign_once) = key_manager
            .prepare_ephemeral_signing(
                &Codec::Ed25519Priv,
                NonZero::new(1).unwrap(),
                NonZero::new(1).unwrap(),
            )
            .expect("Failed to prepare ephemeral signing");

        // Verify that we got a public key
        assert!(public_key.attr_view().unwrap().is_public_key());

        // Sign the data with the one-time function
        let signature = sign_once(data).expect("Failed to sign with ephemeral key");

        // Create a new multikey for verification since we only have the public key
        let verify_key = public_key.clone();

        // Verify the signature
        let verify_result = verify_key
            .verify_view()
            .unwrap()
            .verify(&signature, Some(data));

        assert!(
            verify_result.is_ok(),
            "Signature verification should succeed"
        );

        tracing::info!("Ephemeral signing test completed successfully");
    }
}
