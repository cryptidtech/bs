// SPDX-License-Identifier: FSL-1.1
use std::path::PathBuf;
use structopt::StructOpt;

/// Plog commands
#[derive(Debug, StructOpt)]
pub enum Command {
    /// Open a new provenance log
    #[structopt(name = "open")]
    Open {
        /// The kind of public key pair to use for creating the VLAD.
        /// One of: 'eddsa', 'es256k', 'blsg1', 'blsg2', 'lamport'.
        #[structopt(long = "vlad-key", default_value = "eddsa")]
        vlad_key_codec: String,

        /// The hash function to use when creating the CID in the VLAD.
        /// One of: 'blake2b', 'blake2s', 'blake3', 'sha2', 'sha3'
        #[structopt(long = "cid-hash", default_value = "blake3")]
        vlad_cid_codec: String,

        /// The CID hash length for creating the VLAD
        /// One of: '256', '384', '512'
        #[structopt(long = "hash-length", default_value = "256")]
        vlad_cid_len: String,

        /// The kind of public key pair to use for signing the first entry.
        /// One of: 'eddsa', 'es256k', 'blsg1', 'blsg2', 'lamport'.
        #[structopt(long = "entry-key", default_value = "eddsa")]
        entry_key_codec: String,

        /// The kind of public key pair to advertise as the public key.
        /// One of: 'eddsa', 'es256k', 'blsg1', 'blsg2'
        #[structopt(long = "pub-key", default_value = "eddsa")]
        pub_key_codec: String,

        /// The lock script for verifying the first entry.
        #[structopt(long = "first", parse(from_os_str))]
        first_lock_script_path: PathBuf,

        /// The lock script for verifying the next entry.
        #[structopt(long = "lock", parse(from_os_str))]
        lock_script_path: PathBuf,

        /// The unlock script for providing proof for the first lock script.
        #[structopt(long = "unlock", parse(from_os_str))]
        unlock_script_path: PathBuf,

        /// The output file to write the log to
        #[structopt(short = "o", parse(from_os_str))]
        output: Option<PathBuf>,
    },

    /// Update a provenance log with a new event
    #[structopt(name = "update")]
    Update,

    /// Open a new provenance log as a fork of an existing p.log
    #[structopt(name = "fork")]
    Fork,

    /// Open a new provenance log as the child of multiple existing p.logs
    #[structopt(name = "merge")]
    Merge,

    /// Close an exsting p.log
    #[structopt(name = "close")]
    Close
}
