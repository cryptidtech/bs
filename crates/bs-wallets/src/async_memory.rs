// SPDX-License-Identifier: FSL-1.1
//! Async implementation for the in-memory wallet.

use bs_traits::asyncro::{AsyncKeyManager, AsyncMultiSigner, AsyncSigner, BoxFuture, SignerFuture};
use bs_traits::sync::{EphemeralSigningTuple, SyncGetKey, SyncPrepareEphemeralSigning, SyncSigner};
use bs_traits::{CondSync, EphemeralKey, GetKey, Signer};
use multicodec::Codec;
use multikey::Multikey;
use multisig::Multisig;
use provenance_log::Key;
use std::num::NonZeroUsize;

// Reuse the existing struct definition from memory.rs
pub use crate::memory::InMemoryKeyManager;

impl<E> AsyncSigner for InMemoryKeyManager<E>
where
    E: From<multikey::Error>
        + From<multihash::Error>
        + From<multicid::Error>
        + From<crate::Error>
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
    Self: SyncSigner<KeyPath = Key, Signature = Multisig, Error = E>,
    <Self as Signer>::KeyPath: CondSync,
{
    fn try_sign<'a>(
        &'a self,
        key_path: &'a Self::KeyPath,
        data: &'a [u8],
    ) -> SignerFuture<'a, Self::Signature, Self::Error> {
        Box::pin(async move { SyncSigner::try_sign(self, key_path, data) })
    }
}

impl<E> AsyncKeyManager<E> for InMemoryKeyManager<E>
where
    E: From<multikey::Error> + From<multihash::Error> + std::fmt::Debug + Send + Sync + 'static,
    Self: SyncGetKey<Key = Multikey, Error = E, KeyPath = Key, Codec = Codec>,
    <Self as GetKey>::KeyPath: CondSync,
    <Self as GetKey>::Codec: CondSync,
{
    fn get_key<'a>(
        &'a self,
        key_path: &'a Self::KeyPath,
        codec: &'a Self::Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> BoxFuture<'a, Result<Self::Key, E>> {
        Box::pin(async move { SyncGetKey::get_key(self, key_path, codec, threshold, limit) })
    }
}

impl<E> AsyncMultiSigner<Multisig, E> for InMemoryKeyManager<E>
where
    E: From<multikey::Error>
        + From<multihash::Error>
        + From<multicid::Error>
        + From<crate::Error>
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
    Self: SyncPrepareEphemeralSigning<
            Codec = Codec,
            PubKey = Multikey,
            Signature = Multisig,
            Error = E,
        > + EphemeralKey<PubKey = Multikey>
        + GetKey<Codec = Codec>
        + Signer<Signature = Multisig, Error = E, KeyPath = Key>,
    <Self as GetKey>::Codec: CondSync,
    <Self as Signer>::KeyPath: CondSync,
{
    fn prepare_ephemeral_signing<'a>(
        &'a self,
        codec: &'a <Self as GetKey>::Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> BoxFuture<'a, EphemeralSigningTuple<Self::PubKey, Multisig, E>> {
        Box::pin(async move {
            SyncPrepareEphemeralSigning::prepare_ephemeral_signing(self, codec, threshold, limit)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bs_traits::asyncro::{AsyncKeyManager, AsyncMultiSigner, AsyncSigner};
    use multicodec::Codec;
    use multikey::Views;
    use std::num::NonZero;
    use tracing_subscriber::fmt;

    fn init_logger() {
        let subscriber = fmt().with_env_filter("trace").finish();
        if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
            tracing::warn!("failed to set subscriber: {}", e);
        }
    }

    // Test fixture that ensures async traits are properly implemented
    async fn test_async_traits<KM, MS>(_km: &KM, _ms: &MS)
    where
        KM: AsyncKeyManager<crate::Error, Key = Multikey, KeyPath = Key, Codec = Codec>,
        MS: AsyncMultiSigner<Multisig, crate::Error, PubKey = Multikey, Codec = Codec>,
    {
    }

    #[tokio::test]
    async fn test_async_default_key_manager() {
        // Create key manager with default error type
        let key_manager = InMemoryKeyManager::default();
        test_async_traits(&key_manager, &key_manager).await;
    }

    #[tokio::test]
    async fn test_async_key_manager() {
        // Create key manager
        let key_manager = InMemoryKeyManager::<crate::Error>::new();

        // Test a regular non-ephemeral key
        let key_path = Key::try_from("/async/test/key/path").unwrap();
        let test_mk =
            multikey::Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rand_core_6::OsRng)
                .unwrap()
                .try_build()
                .unwrap();

        // Add to wallet
        key_manager
            .store_secret_key(key_path.clone(), test_mk.clone())
            .unwrap();

        // Can sign with stored key using async API
        let data = b"test async data";
        let signature = AsyncSigner::try_sign(&key_manager, &key_path, data)
            .await
            .unwrap();
        let verify_result = test_mk
            .verify_view()
            .unwrap()
            .verify(&signature, Some(data));
        assert!(verify_result.is_ok());
    }

    #[tokio::test]
    async fn test_async_dynamic_key_generation() {
        // Create key manager
        let key_manager = InMemoryKeyManager::<crate::Error>::new();

        // Request a key with a custom path using async API
        let custom_path = Key::try_from("/async/custom/key/path").unwrap();

        // First call to get_key generates a key pair and stores the secret key,
        // but returns the public key
        let public_key = AsyncKeyManager::get_key(
            &key_manager,
            &custom_path,
            &Codec::Ed25519Priv,
            NonZero::new(1).unwrap(),
            NonZero::new(1).unwrap(),
        )
        .await
        .unwrap();

        // Verify we got a public key
        assert!(public_key.attr_view().unwrap().is_public_key());

        // Get the key again - should be the same public key
        let public_key2 = AsyncKeyManager::get_key(
            &key_manager,
            &custom_path,
            &Codec::Ed25519Priv,
            NonZero::new(1).unwrap(),
            NonZero::new(1).unwrap(),
        )
        .await
        .unwrap();

        assert!(
            public_key.eq(&public_key2),
            "The two retrieved public keys should be equal"
        );

        // Try signing with the key at the custom path using async API
        // This works because the secret key is stored internally in the key manager
        let data = b"test async custom key";
        let signature = AsyncSigner::try_sign(&key_manager, &custom_path, data)
            .await
            .unwrap();

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
    async fn test_async_prepare_ephemeral_signing() {
        init_logger();

        tracing::info!("Starting test_async_prepare_ephemeral_signing");

        let key_manager = InMemoryKeyManager::<crate::Error>::new();
        let data = b"test async ephemeral signing";

        // Use async API to get an ephemeral public key and a one-time signing function
        let (public_key, sign_once) = AsyncMultiSigner::prepare_ephemeral_signing(
            &key_manager,
            &Codec::Ed25519Priv,
            NonZero::new(1).unwrap(),
            NonZero::new(1).unwrap(),
        )
        .await
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

        tracing::info!("Async ephemeral signing test completed successfully");
    }

    #[tokio::test]
    async fn test_async_concurrent_key_generation() {
        // Test that multiple concurrent async operations work correctly
        let key_manager = InMemoryKeyManager::<crate::Error>::new();

        // Create multiple tasks that generate keys concurrently
        let mut handles = vec![];
        for i in 0..5 {
            let km = key_manager.clone();
            let handle = tokio::spawn(async move {
                let path = Key::try_from(format!("/concurrent/key/{}", i).as_str()).unwrap();
                AsyncKeyManager::get_key(
                    &km,
                    &path,
                    &Codec::Ed25519Priv,
                    NonZero::new(1).unwrap(),
                    NonZero::new(1).unwrap(),
                )
                .await
                .unwrap()
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        let mut public_keys = vec![];
        for handle in handles {
            let pk = handle.await.unwrap();
            assert!(pk.attr_view().unwrap().is_public_key());
            public_keys.push(pk);
        }

        // All keys should be unique
        for i in 0..public_keys.len() {
            for j in (i + 1)..public_keys.len() {
                assert!(
                    !public_keys[i].eq(&public_keys[j]),
                    "Keys {} and {} should be different",
                    i,
                    j
                );
            }
        }
    }

    #[tokio::test]
    async fn test_async_concurrent_signing() {
        // Test that multiple concurrent async signing operations work correctly
        let key_manager = InMemoryKeyManager::<crate::Error>::new();

        // Generate a shared key
        let key_path = Key::try_from("/shared/signing/key").unwrap();
        let _ = AsyncKeyManager::get_key(
            &key_manager,
            &key_path,
            &Codec::Ed25519Priv,
            NonZero::new(1).unwrap(),
            NonZero::new(1).unwrap(),
        )
        .await
        .unwrap();

        // Create multiple tasks that sign data concurrently
        let mut handles = vec![];
        for i in 0..5 {
            let km = key_manager.clone();
            let kp = key_path.clone();
            let handle = tokio::spawn(async move {
                let data = format!("concurrent data {}", i);
                AsyncSigner::try_sign(&km, &kp, data.as_bytes())
                    .await
                    .unwrap()
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        let mut signatures = vec![];
        for handle in handles {
            let sig = handle.await.unwrap();
            signatures.push(sig);
        }

        // All signatures should be valid (we don't check uniqueness as they sign different data)
        assert_eq!(signatures.len(), 5);
    }

    #[tokio::test]
    async fn test_async_multiple_ephemeral_keys() {
        // Test creating multiple ephemeral keys concurrently
        let key_manager = InMemoryKeyManager::<crate::Error>::new();

        let mut handles = vec![];
        for i in 0..3 {
            let km = key_manager.clone();
            let handle = tokio::spawn(async move {
                let (public_key, sign_once) = AsyncMultiSigner::prepare_ephemeral_signing(
                    &km,
                    &Codec::Ed25519Priv,
                    NonZero::new(1).unwrap(),
                    NonZero::new(1).unwrap(),
                )
                .await
                .unwrap();

                let data = format!("ephemeral data {}", i);
                let signature = sign_once(data.as_bytes()).unwrap();

                // Verify the signature
                public_key
                    .verify_view()
                    .unwrap()
                    .verify(&signature, Some(data.as_bytes()))
                    .unwrap();

                public_key
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        let mut public_keys = vec![];
        for handle in handles {
            let pk = handle.await.unwrap();
            public_keys.push(pk);
        }

        // All ephemeral keys should be unique
        for i in 0..public_keys.len() {
            for j in (i + 1)..public_keys.len() {
                assert!(
                    !public_keys[i].eq(&public_keys[j]),
                    "Ephemeral keys {} and {} should be different",
                    i,
                    j
                );
            }
        }
    }
}
