use super::*;
use bs_traits::asyncro::{AsyncGetKey, AsyncSigner};

/// Supertrait for key management operations
pub trait KeyManager:
    GetKey<KeyPath = Key, Codec = Codec, Key = Multikey, Error = Error>
    + AsyncGetKey
    + Send
    + Sync
    + 'static
{
}

/// Supertrait for signing operations
pub trait MultiSigner:
    Signer<KeyPath = Key, Signature = Multisig, Error = Error> + AsyncSigner + Send + Sync + 'static
{
}

impl<T> KeyManager for T where
    T: GetKey<KeyPath = Key, Codec = Codec, Key = Multikey, Error = Error>
        + AsyncGetKey
        + Send
        + Sync
        + 'static
{
}

impl<T> MultiSigner for T where
    T: Signer<KeyPath = Key, Signature = Multisig, Error = Error>
        + AsyncSigner
        + Send
        + Sync
        + 'static
{
}
