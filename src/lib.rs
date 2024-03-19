//!
#![warn(missing_docs)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]

/// Config
pub mod config;
pub use config::Config;

/// Error
pub mod error;
pub use error::Error;

/// Filesystem functions
pub mod fs;
pub use fs::initialize_local_file;

/// Keychain interface
pub mod keychain;
pub use keychain::{Backend, Keychain, KeychainConfig};

/// Local file keychain
pub mod local_file;
pub use local_file::LocalFile;

/// SSH Agent keychain
pub mod ssh_agent;
pub use ssh_agent::SshAgent;

/// ...and in the darkness bind them
pub mod prelude {
    pub use super::*;
}
