// SPDX-License-Idnetifier: Apache-2.0
//! Rand abstraction crate
#![warn(missing_docs)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]

use rand::{RngCore, SeedableRng, TryRngCore};
use std::ops::{Deref, DerefMut};

/// A wrapper around `StdRng` to implement `RngCore` and `CryptoRng` from rand v0.6.4
pub struct StdRng(pub rand::rngs::StdRng);

impl StdRng {
    /// Creates a new `StdRng` instance using a seed from the os entropy source
    pub fn from_os_rng() -> Self {
        Self(rand::rngs::StdRng::from_os_rng())
    }
}

impl Deref for StdRng {
    type Target = rand::rngs::StdRng;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for StdRng {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl rand_core_6::RngCore for StdRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_6::Error> {
        self.0.try_fill_bytes(dest).map_err(rand_core_6::Error::new)
    }
}

impl rand_core_6::CryptoRng for StdRng {}

// NOTE: `rand_core::CryptoRngCore` is automatically defined for all types that also define
// `rand_core::RngCore` and `rand_core::CryptoRng`. This satisfies the `elliptic-curve` v0.13.8
// dependency on `rand_core` v0.6.4 while using `rand_core` v0.9.0
