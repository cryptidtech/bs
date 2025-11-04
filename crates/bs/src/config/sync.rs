//! Sync alterntives to the asynchronous traits.
use bs_traits::sync::{SyncGetKey, SyncPrepareEphemeralSigning, SyncSigner};
use bs_traits::EphemeralKey;

use super::*;

/// Supertrait for key management operations
pub trait KeyManager<E>:
    GetKey<KeyPath = Key, Codec = Codec, Key = Multikey, Error = E> + SyncGetKey
{
}

impl<T, E> KeyManager<E> for T where
    T: GetKey<KeyPath = Key, Codec = Codec, Key = Multikey, Error = E> + SyncGetKey
{
}

/// Supertrait for signing operations
pub trait MultiSigner<E>:
    Signer<KeyPath = Key, Signature = Multisig, Error = E>
    + SyncSigner
    + EphemeralKey<PubKey = Multikey>
    + GetKey<KeyPath = Key, Codec = Codec, Key = Multikey, Error = E>
    + SyncPrepareEphemeralSigning<Codec = Codec>
{
}

impl<T, E> MultiSigner<E> for T where
    T: Signer<KeyPath = Key, Signature = Multisig, Error = E>
        + SyncSigner
        + EphemeralKey<PubKey = Multikey>
        + GetKey<KeyPath = Key, Codec = Codec, Key = Multikey, Error = E>
        + SyncPrepareEphemeralSigning<Codec = Codec>
{
}
