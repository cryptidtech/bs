//! Platform specific code (Browser and Native)

pub(super) mod common;

#[cfg(target_arch = "wasm32")]
mod browser;
#[cfg(not(target_arch = "wasm32"))]
mod native;

use std::future::Future;

#[cfg(target_arch = "wasm32")]
pub use browser::{Error, OPFSWrapped as Blockstore};

#[cfg(not(target_arch = "wasm32"))]
pub use native::{Error, NativeBlockstore as Blockstore};

// #[cfg(target_arch = "wasm32")]
// pub use peerpiper_browser::{start, StartConfig};
//
// #[cfg(not(target_arch = "wasm32"))]
// pub use native::{start, StartConfig};

/// Spawn for tokio
// allow dead
#[allow(unused)]
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn(f: impl Future<Output = ()> + Send + 'static) {
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
