//! Sync alterntives to the asynchronous traits.
use bs_traits::{SyncGetKey, SyncSigner};

use super::*;

/// Supertrait for key management operations
pub trait KeyManager<E>:
    GetKey<KeyPath = Key, Codec = Codec, Key = Multikey, Error = E> + SyncGetKey
{
}

/// Supertrait for signing operations
pub trait MultiSigner<E>:
    Signer<Key = Multikey, Signature = Multisig, Error = E> + SyncSigner
{
}

impl<T, E> KeyManager<E> for T where
    T: GetKey<KeyPath = Key, Codec = Codec, Key = Multikey, Error = E> + SyncGetKey
{
}

impl<T, E> MultiSigner<E> for T where
    T: Signer<Key = Multikey, Signature = Multisig, Error = E> + SyncSigner
{
}

/// Trait for key providers that have standardized paths
pub trait KeyPathProvider {
    /// Path for the Vlad key operations
    const VLAD_KEY_PATH: &'static str;
    /// Path for the public key operations
    const PUBKEY_KEY_PATH: &'static str;
}
