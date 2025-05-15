//! Utilities for conditionally adding `Send` and `Sync` constraints.

/// A conditionally compiled trait indirection for `Send` bounds.
/// This target makes it require `Send`.
#[cfg(not(target_arch = "wasm32"))]
pub trait CondSend: Send {}

/// A conditionally compiled trait indirection for `Send` bounds.
/// This target makes it not require any marker traits.
#[cfg(target_arch = "wasm32")]
pub trait CondSend {}

#[cfg(not(target_arch = "wasm32"))]
impl<S> CondSend for S where S: Send {}

#[cfg(target_arch = "wasm32")]
impl<S> CondSend for S {}

/// A conditionally compiled trait indirection for `Send + Sync` bounds.
/// This target makes it require `Send + Sync`.
#[cfg(not(target_arch = "wasm32"))]
pub trait CondSync: Send + Sync {}

/// A conditionally compiled trait indirection for `Send + Sync` bounds.
/// This target makes it not require any marker traits.
#[cfg(target_arch = "wasm32")]
pub trait CondSync {}

#[cfg(not(target_arch = "wasm32"))]
impl<S> CondSync for S where S: Send + Sync {}

#[cfg(target_arch = "wasm32")]
impl<S> CondSync for S {}
