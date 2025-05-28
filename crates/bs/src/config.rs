//! Holds opinionated configuration about what concrete types should be used for the traits.
//!
//! Users can pick any concrete types that implement the traits, but this module provides
//! default implementations that can be used directly.

/// Opinionated configuration for the async traits types
pub mod asynchronous;
/// Opinionated configuration for the sync traits types
pub mod sync;

use crate::Error;
use bs_traits::{GetKey, Signer};

/// Re-export the types used in the traits
pub use multicodec::Codec;
pub use multikey::Multikey;
pub use multisig::Multisig;
pub use provenance_log::Key;
