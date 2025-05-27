//! In memory Key manager and signer
use crate::peer::{p::*, KeyGetterTrait, SignerTrait};
use bs_traits::{AsyncGetKey, AsyncSigner, GetKey, GetKeyFuture, Signer};

#[derive(Debug, Clone, Default)]
pub(crate) struct InMemoryKeyManager {
    vlad: Option<Multikey>,
    entry_key: Option<Multikey>,
}

impl GetKey for InMemoryKeyManager {
    type KeyPath = Key;
    type Codec = Codec;
    type Key = Multikey;
    type Error = crate::Error;
}

impl AsyncGetKey for InMemoryKeyManager {
    fn get_key<'a>(
        &'a self,
        key_path: &'a Self::KeyPath,
        codec: &'a Self::Codec,
        threshold: usize,
        limit: usize,
    ) -> GetKeyFuture<'a, Self::Key, Self::Error> {
        todo!()
    }
}
