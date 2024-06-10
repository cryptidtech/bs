// SPDX-License-Identifier: FSL-1.1

/// Definition for the "key" cli sub-command
pub mod command;
pub use command::KeyCommand;

/// Definition of key errors
pub mod error;
pub use error::Error;

/// The async function to start the state machine for key generation
pub mod gen;
pub use gen::gen;
