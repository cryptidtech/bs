// SPDX-License-Identifier: FSL-1.1

/// Open operation
pub mod open;
pub use open::open;

/// Update operation
pub mod update;
pub use update::{op, script, update};

/// Handy export for all public symbols
pub mod prelude {
    pub use super::*;
}
