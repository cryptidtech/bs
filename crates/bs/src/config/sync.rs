//! Synchronous trait supertraits with opinionated concrete types for BetterSign.
//!
//! This module provides convenience supertraits that combine the generic synchronous traits
//! from `bs_traits::sync` with concrete types specific to the BetterSign application.
//!
//! # Purpose
//!
//! Rather than repeating verbose trait bounds throughout the codebase:
//! ```ignore
//! fn example<KM, E>(
//!     key_manager: &KM
//! ) where
//!     KM: bs_traits::sync::SyncGetKey<
//!         KeyPath = provenance_log::Key,
//!         Codec = multicodec::Codec,
//!         Key = multikey::Multikey,
//!         Error = E
//!     >
//! ```
//!
//! You can use the opinionated supertraits from this module:
//! ```ignore
//! use bs::config::sync::KeyManager;
//!
//! fn example<E>(key_manager: &(dyn KeyManager<E> + Send + Sync))
//! ```
//!
//! # Relationship to Other Modules
//!
//! - **`bs_traits::sync`**: Provides generic synchronous traits that work with any types
//! - **`bs::config::sync`** (this module): Provides opinionated supertraits with concrete types for BetterSign
//! - **`bs::config::asynchronous`**: Parallel module providing async supertraits
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
//! use bs::config::sync::{KeyManager, MultiSigner};
//!
//! fn process_sync<E>(
//!     km: &(dyn KeyManager<E> + Send + Sync),
//!     signer: &(dyn MultiSigner<E> + Send + Sync),
//! ) -> Result<(), E> {
//!     // All concrete types are already specified in the trait bounds
//!     // ...
//! }
//! ```
pub use bs_traits::sync::{SyncGetKey, SyncPrepareEphemeralSigning, SyncSigner};
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
