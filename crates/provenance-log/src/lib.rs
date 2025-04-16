// SPDX-License-Identifier: FSL-1.1
//! provenance-log
#![warn(missing_docs)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]

/// Provenance log entry related functions
pub mod entry;
pub use entry::{EncodedEntry, Entry};

/// Errors produced by this library
pub mod error;
pub use error::Error;

/// Key-path used in the Kvp
pub mod key;
pub use key::Key;

/// Lipmaa numbering for sequence numbers
pub mod lipmaa;
pub use lipmaa::Lipmaa;

/// Provenance log related functions
pub mod log;
pub use log::{EncodedLog, Log};

/// Ops for the plog virtual namespace
pub mod op;
pub use op::{Op, OpId};

/// The virtual key-value pair store
pub mod pairs;
pub use pairs::Kvp;

/// Script related functions
pub mod script;
pub use script::{EncodedScript, Script, ScriptId};

/// Serde serialization
#[cfg(feature = "serde")]
pub mod serde;

/// The parameter and return value stack type 
pub mod stack;
pub use stack::Stk;

/// Entry Value related functions
pub mod value;
pub use value::{Value, ValueId};

/// ...and in the darkness bind them
pub mod prelude {
    pub use super::*;
    /// re-exports
    pub use multibase::Base;
    pub use multicodec::Codec;
    pub use multiutil::BaseEncoded;
}
