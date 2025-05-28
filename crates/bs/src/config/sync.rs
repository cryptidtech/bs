//! Sync alterntives to the asynchronous traits.
use bs_traits::{SyncGetKey, SyncSigner};

use super::*;

/// Supertrait for key management operations
pub trait KeyManager<E>:
    GetKey<KeyPath = Key, Codec = Codec, Key = Multikey, Error = E> + SyncGetKey + Send + Sync + 'static
{
}

/// Supertrait for signing operations
pub trait MultiSigner<E>:
    Signer<Key = Multikey, Signature = Multisig, Error = E> + SyncSigner + Send + Sync + 'static
{
}

impl<T, E> KeyManager<E> for T where
    T: GetKey<KeyPath = Key, Codec = Codec, Key = Multikey, Error = E>
        + SyncGetKey
        + Send
        + Sync
        + 'static
{
}

impl<T, E> MultiSigner<E> for T where
    T: Signer<Key = Multikey, Signature = Multisig, Error = E> + SyncSigner + Send + Sync + 'static
{
}
