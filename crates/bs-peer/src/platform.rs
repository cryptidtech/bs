//! Platform specific code (Browser and Native)
use bs_traits::CondSend;
pub(super) mod common;
pub use common::RawBlakeBlock;

/// Wasm32 platform code for browsers
#[cfg(target_arch = "wasm32")]
mod browser;

/// Native platform code for non-WASM targets
#[cfg(not(target_arch = "wasm32"))]
mod native;

use std::future::Future;

#[cfg(target_arch = "wasm32")]
pub use browser::{start, Error, OPFSWrapped as Blockstore, StartConfig};

#[cfg(not(target_arch = "wasm32"))]
pub use native::{start, NativeBlockstore as Blockstore, NativeError as Error, StartConfig};

// #[cfg(target_arch = "wasm32")]
// pub use peerpiper_browser::{start, StartConfig};
//
// #[cfg(not(target_arch = "wasm32"))]
// pub use native::{start, };

/// Spawn for tokio
// allow dead
#[allow(unused)]
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn(f: impl Future<Output = ()> + CondSend + 'static) {
    tokio::spawn(f);
}

/// Spawn for browser wasm32
// allow dead
#[allow(dead_code)]
#[cfg(target_arch = "wasm32")]
pub fn spawn(f: impl Future<Output = ()> + 'static) {
    tracing::debug!("Spawning wasm_bingen future");
    wasm_bindgen_futures::spawn_local(f);
}
