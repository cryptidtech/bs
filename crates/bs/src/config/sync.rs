//! Sync alterntives to the asynchronous traits.
use bs_traits::{SyncGetKey, SyncSigner};

use super::*;

/// Supertrait for key management operations
pub trait KeyManager:
    GetKey<KeyPath = Key, Codec = Codec, Key = Multikey, Error = Error>
    + SyncGetKey
    + Send
    + Sync
    + 'static
{
}

/// Supertrait for signing operations
pub trait MultiSigner:
    Signer<Key = Multikey, Signature = Multisig, Error = Error> + SyncSigner + Send + Sync + 'static
{
}

impl<T> KeyManager for T where
    T: GetKey<KeyPath = Key, Codec = Codec, Key = Multikey, Error = Error>
        + SyncGetKey
        + Send
        + Sync
        + 'static
{
}

impl<T> MultiSigner for T where
    T: Signer<Key = Multikey, Signature = Multisig, Error = Error>
        + SyncSigner
        + Send
        + Sync
        + 'static
{
}
