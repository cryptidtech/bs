// SPDX-License-Identifier: FSL-1.1
//! Adapters to bridge sync traits to async traits.

use crate::config::sync::{KeyManager, MultiSigner};
use crate::Error;
use bs_traits::asyncro::{AsyncKeyManager, AsyncMultiSigner};
use bs_traits::asyncro::{AsyncSigner, BoxFuture, SignerFuture};
use bs_traits::sync::EphemeralSigningTuple;
use bs_traits::{self, EphemeralKey, GetKey, Signer};
use multicodec::Codec;
use multikey::Multikey;
use multisig::Multisig;
use provenance_log::Key;
use std::marker::PhantomData;
use std::num::NonZeroUsize;

/// An adapter that wraps a sync `KeyManager` to expose an `AsyncKeyManager` interface.
pub struct SyncToAsyncManager<'a, E: 'a> {
    sync_manager: &'a (dyn KeyManager<E> + Send + Sync),
    _phantom: PhantomData<E>,
}

impl<'a, E> SyncToAsyncManager<'a, E> {
    /// Create a new [`SyncToAsyncManager`] wrapping the given sync [`KeyManager`].
    pub fn new(sync_manager: &'a (dyn KeyManager<E> + Send + Sync)) -> Self {
        Self {
            sync_manager,
            _phantom: PhantomData,
        }
    }
}

impl<'a, E> GetKey for SyncToAsyncManager<'a, E>
where
    E: From<multikey::Error> + From<multihash::Error> + std::fmt::Debug + Send + Sync + 'static,
{
    type Key = Multikey;
    type KeyPath = Key;
    type Codec = Codec;
    type Error = E;
}

impl<'a, E> AsyncKeyManager<E> for SyncToAsyncManager<'a, E>
where
    E: From<multikey::Error> + From<multihash::Error> + std::fmt::Debug + Send + Sync + 'static,
{
    fn get_key(
        &self,
        key_path: &<Self as GetKey>::KeyPath,
        codec: &<Self as GetKey>::Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> BoxFuture<'_, Result<<Self as GetKey>::Key, E>> {
        let res = self.sync_manager.get_key(key_path, codec, threshold, limit);
        Box::pin(async { res })
    }
}

/// An adapter that wraps a sync `MultiSigner` to expose an `AsyncMultiSigner` interface.
pub struct SyncToAsyncSigner<'a, E: 'a> {
    sync_signer: &'a (dyn MultiSigner<E> + Send + Sync),
    _phantom: PhantomData<E>,
}

impl<'a, E> SyncToAsyncSigner<'a, E> {
    /// Create a new [`SyncToAsyncSigner`] wrapping the given sync [`MultiSigner`].
    pub fn new(sync_signer: &'a (dyn MultiSigner<E> + Send + Sync)) -> Self {
        Self {
            sync_signer,
            _phantom: PhantomData,
        }
    }
}

impl<'a, E> Signer for SyncToAsyncSigner<'a, E>
where
    E: From<multikey::Error>
        + From<multihash::Error>
        + From<multicid::Error>
        + From<Error>
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
{
    type KeyPath = Key;
    type Signature = Multisig;
    type Error = E;
}

impl<'a, E> EphemeralKey for SyncToAsyncSigner<'a, E>
where
    E: From<multikey::Error>
        + From<multihash::Error>
        + From<multicid::Error>
        + From<Error>
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
{
    type PubKey = Multikey;
}

impl<'a, E> AsyncSigner for SyncToAsyncSigner<'a, E>
where
    E: From<multikey::Error>
        + From<multihash::Error>
        + From<multicid::Error>
        + From<Error>
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
{
    fn try_sign<'b>(
        &'b self,
        key_path: &'b <Self as Signer>::KeyPath,
        data: &'b [u8],
    ) -> SignerFuture<'b, <Self as Signer>::Signature, <Self as Signer>::Error> {
        let res = self.sync_signer.try_sign(key_path, data);
        Box::pin(async { res })
    }
}

impl<'a, E> AsyncMultiSigner<Multisig, E> for SyncToAsyncSigner<'a, E>
where
    E: From<multikey::Error>
        + From<multihash::Error>
        + From<multicid::Error>
        + From<Error>
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
{
    fn prepare_ephemeral_signing<'b>(
        &'b self,
        codec: &'b <Self as GetKey>::Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> BoxFuture<'b, EphemeralSigningTuple<<Self as EphemeralKey>::PubKey, Multisig, E>> {
        let res = self
            .sync_signer
            .prepare_ephemeral_signing(codec, threshold, limit);
        Box::pin(async { res })
    }
}

impl<'a, E> GetKey for SyncToAsyncSigner<'a, E>
where
    E: 'a,
{
    type Key = Multikey;
    type KeyPath = Key;
    type Codec = Codec;
    type Error = E;
}
