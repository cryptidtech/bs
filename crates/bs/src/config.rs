//! Opinionated configuration layer for BetterSign trait bounds with concrete types.
//!
//! # Architecture Overview
//!
//! This module provides a convenience layer on top of the generic traits from `bs-traits`,
//! eliminating repetitive type parameter boilerplate throughout the BetterSign codebase.
//!
//! ## Layered Design
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │  Application Layer (bs-peer, bs-wallets, etc.)      │
//! │  Uses: config::sync::KeyManager<E>                  │
//! │        config::asynchronous::MultiSigner<E>         │
//! └─────────────────────────────────────────────────────┘
//!                         ↓
//! ┌─────────────────────────────────────────────────────┐
//! │  Configuration Layer (this module)                  │
//! │  Provides: Opinionated supertraits with concrete    │
//! │  types (Key, Codec, Multikey, Multisig)             │
//! └─────────────────────────────────────────────────────┘
//!                         ↓
//! ┌─────────────────────────────────────────────────────┐
//! │  Traits Layer (bs-traits)                           │
//! │  Provides: Generic sync/async traits                │
//! │  (SyncSigner, AsyncSigner, etc.)                    │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! ## Modules
//!
//! - **`sync`**: Synchronous supertraits combining `bs_traits::sync` traits with concrete types
//! - **`asynchronous`**: Asynchronous supertraits combining `bs_traits::asyncro` traits with concrete types
//! - **`adapters`**: Bridges that convert sync trait implementations to async interfaces
//!
//! ## Concrete Types
//!
//! This configuration layer standardizes on these concrete types:
//!
//! - **Key paths**: [`provenance_log::Key`]
//! - **Codec**: [`multicodec::Codec`]
//! - **Public keys**: [`multikey::Multikey`]
//! - **Signatures**: [`multisig::Multisig`] (re-exported as [`crate::Signature`])
//!
//! ## Benefits
//!
//! 1. **Reduced boilerplate**: Write `KeyManager<E>` instead of repeating all associated types
//! 2. **Type safety**: Ensures consistent concrete types across the application
//! 3. **Flexibility**: Generic over error type `E` for different error handling strategies
//! 4. **Maintainability**: Change concrete types in one place if needed
//!
//! ## When to Use
//!
//! - **Use this module** when writing BetterSign-specific code that uses the standard concrete types
//! - **Use `bs-traits` directly** when writing generic code that should work with any types
//!
//! ## Example
//!
//! ```ignore
//! // Without config module (verbose)
//! use bs_traits::asyncro::AsyncKeyManager;
//! use multicodec::Codec;
//! use multikey::Multikey;
//! use provenance_log::Key;
//!
//! async fn verbose<KM, E>(km: &KM) -> Result<Multikey, E>
//! where
//!     KM: AsyncKeyManager<E, KeyPath = Key, Codec = Codec, Key = Multikey>,
//! {
//!     // ...
//! }
//!
//! // With config module (clean)
//! use bs::config::asynchronous::KeyManager;
//!
//! async fn clean<E: Send>(km: &(dyn KeyManager<E> + Send + Sync)) -> Result<bs::config::Multikey, E> {
//!     // ...
//! }
//! ```

/// Sync to async adapters
pub mod adapters;
/// Opinionated configuration for the async traits types
pub mod asynchronous;
/// Opinionated configuration for the sync traits types
pub mod sync;

use bs_traits::{GetKey, Signer};

/// Re-export the types used in the traits
pub use multicodec::Codec;
pub use multikey::Multikey;
pub use multisig::Multisig;
pub use provenance_log::Key;

/// The concrete signature type used throughout BetterSign.
///
/// This is an alias for [`multisig::Multisig`] and is the standard signature type
/// used in both [`sync::MultiSigner`] and [`asynchronous::MultiSigner`] traits.
///
/// # Example
///
/// ```ignore
/// use bs::config::Signature;
///
/// fn verify_signature(sig: &Signature) {
///     // Work with the concrete signature type
/// }
/// ```
pub type Signature = Multisig;
