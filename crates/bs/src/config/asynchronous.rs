//! Asynchronous trait supertraits with opinionated concrete types for BetterSign.
//!
//! This module provides convenience supertraits that combine the generic asynchronous traits
//! from `bs_traits::asyncro` with concrete types specific to the BetterSign application.
//!
//! # Purpose
//!
//! Rather than repeating verbose trait bounds throughout the codebase:
//! ```ignore
//! async fn example<KM, S, E>(
//!     key_manager: &KM,
//!     signer: &S,
//! ) -> Result<(), E>
//! where
//!     KM: bs_traits::asyncro::AsyncKeyManager<
//!         E,
//!         KeyPath = provenance_log::Key,
//!         Codec = multicodec::Codec,
//!         Key = multikey::Multikey,
//!     >,
//!     S: bs_traits::asyncro::AsyncMultiSigner<
//!         multisig::Multisig,
//!         E,
//!         PubKey = multikey::Multikey,
//!         Codec = multicodec::Codec,
//!     >,
//! ```
//!
//! You can use the opinionated supertraits from this module:
//! ```ignore
//! use bs::config::asynchronous::{KeyManager, MultiSigner};
//!
//! async fn example<E: Send>(
//!     key_manager: &(dyn KeyManager<E> + Send + Sync),
//!     signer: &(dyn MultiSigner<E> + Send + Sync),
//! ) -> Result<(), E>
//! ```
//!
//! # Relationship to Other Modules
//!
//! - **`bs_traits::asyncro`**: Provides generic asynchronous traits that work with any types
//! - **`bs::config::asynchronous`** (this module): Provides opinionated supertraits with concrete types for BetterSign
//! - **`bs::config::sync`**: Parallel module providing synchronous supertraits
//! - **`bs::config::adapters`**: Bridges between sync and async implementations
//!
//! # Concrete Types Used
//!
//! - **KeyPath**: `provenance_log::Key`
//! - **Codec**: `multicodec::Codec`
//! - **Key**: `multikey::Multikey`
//! - **Signature**: `multisig::Multisig` (aliased as `bs::Signature`)
//!
//! # Example
//!
//! ```ignore
//! use bs::config::asynchronous::{KeyManager, MultiSigner};
//!
//! async fn process_async<E: Send>(
//!     km: &(dyn KeyManager<E> + Send + Sync),
//!     signer: &(dyn MultiSigner<E> + Send + Sync),
//! ) -> Result<(), E> {
//!     // All concrete types are already specified in the trait bounds
//!     // ...
//! }
//! ```
use super::*;
pub use bs_traits::asyncro::{
    AsyncKeyManager as AsyncGetKeyTrait, AsyncMultiSigner as AsyncMultiSignerTrait, AsyncSigner,
};
use bs_traits::EphemeralKey;

/// Supertrait for key management operations
pub trait KeyManager<E>:
    GetKey<KeyPath = Key, Codec = Codec, Key = Multikey, Error = E>
    + AsyncGetKeyTrait<E>
    + Send
    + Sync
    + 'static
{
}

impl<T, E> KeyManager<E> for T where
    T: GetKey<KeyPath = Key, Codec = Codec, Key = Multikey, Error = E>
        + AsyncGetKeyTrait<E>
        + Send
        + Sync
        + 'static
{
}

/// Supertrait for signing operations
pub trait MultiSigner<E>:
    Signer<KeyPath = Key, Signature = Multisig, Error = E>
    + AsyncSigner
    + EphemeralKey<PubKey = Multikey>
    + GetKey<KeyPath = Key, Codec = Codec, Key = Multikey, Error = E>
    + AsyncMultiSignerTrait<Multisig, E, Codec = Codec>
    + Send
    + Sync
    + 'static
where
    E: Send,
{
}

impl<T, E> MultiSigner<E> for T
where
    T: Signer<KeyPath = Key, Signature = Multisig, Error = E>
        + AsyncSigner
        + EphemeralKey<PubKey = Multikey>
        + GetKey<KeyPath = Key, Codec = Codec, Key = Multikey, Error = E>
        + AsyncMultiSignerTrait<Multisig, E, Codec = Codec>
        + Send
        + Sync
        + 'static,
    E: Send,
{
}
