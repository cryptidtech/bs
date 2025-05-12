// SPDX-License-Identifier: FSL-1.1

/// `bs-traits` is a crate that provides traits for asynchronous and synchronous operations.
///
/// It also provides a `WaitQueue` type that can be used to implement synchronous and asynchronous operations
/// without having to use tokio::block_in_place or similar.
mod r#async;
mod error;
mod sync;
mod wait_queue;

pub use error::Error;
pub use r#async::*;
pub use sync::*;
pub use wait_queue::*;
