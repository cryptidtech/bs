// SPDX-License-Identifier: FSL-1.1
use std::path::PathBuf;
use structopt::StructOpt;

/// Plog commands
#[derive(Debug, StructOpt)]
pub enum Command {
    /// Close an exsting p.log
    #[structopt(name = "close")]
    Close,

    /// Open a new provenance log as a fork of an existing p.log
    #[structopt(name = "fork")]
    Fork,

    /// Open a new provenance log as the child of multiple existing p.logs
    #[structopt(name = "merge")]
    Merge,

    /// Open a new provenance log
    #[structopt(name = "open")]
    Open {
        /// The parameters for the generation of the advertised public key.
        ///
        /// Values are made up of one to three fields separated by colons. The last two are
        /// optional. If the threshold and limit values are not specified, '1' is used for both
        /// which disables threshold signing. A threshold signature uses Shamir Key splitting over
        /// gf256 and is currently only supported by 'blsg1', 'blsg2', and 'lamport' keys. They key
        /// shares after splitting are used to create signature shares. The signature can be
        /// reconstructed when <threshold> number of shares out of <limit> total shares are
        /// gathered.
        ///
        /// Be warned that 'lamport' signature are one-time-use signatures so it doesn't make much
        /// sense to advertise a 'lamport' key as your public key unless you intend to only sign
        /// once. In that case, you need to build a lock script that requires the next entry to
        /// update the `/pubkey` value.
        ///
        /// <key codec>[:<threshold number>:<limit number>]
        ///
        /// The key codec can be one of: 'eddsa', 'es256k', 'blsg1', 'blsg2', 'lamport'
        ///
        /// Examples:
        ///     'es256k'
        ///     'lamport:5:5'
        ///     'blsg1:3:5'
        #[structopt(long = "pub-key", default_value = "eddsa")]
        pub_key_params: String,

        /// The parameters for key generation and advertisement. This may be used multiple times,
        /// as needed.
        ///
        /// Values are made up of two to five fields separated by colons, the last three fields are
        /// optional. The threshold and limit values are for when you want to create a threshold
        /// signature group and publish the public key. The revoke field is a boolean that
        /// determines if revocation should be signaled by first deleting the key path before
        /// setting a new key.
        ///
        /// <key-path>:<key codec>[:<threshold>:<limit>:<revoke>]
        ///
        /// Examples:
        ///     '/emailkey:eddsa'
        ///     '/recoverykey:lamport:3:5'
        #[structopt(long = "key-op")]
        key_ops: Vec<String>,

        /// The parameters for storing strings in the p.log. This is useful for storing textual
        /// data such as meta data, endoint URLs, peer IDs, multiaddrs, whatever. This may be used
        /// multiple times, as needed.
        ///
        /// Values are made up of two fields separated by colons.
        ///
        /// <key-path>:<string>
        ///
        /// Examples:
        ///     '/contact/email:dwg@linuxprogrammer.org'
        ///     '/contact/name:Dave Grantham'
        ///     '/contact/telegram: @dwgrantham'
        #[structopt(long = "string-op")]
        string_ops: Vec<String>,

        /// The parameters for storing/reference files in the p.log. This is most useful for
        /// tracking the provenance of data in external files. This may be used multiple times, as
        /// needed.
        ///
        /// Values are made up of two to six fields, the last four are optional. The 'inline'
        /// field is either 'true' or 'false' with the default being 'false'. When true, the
        /// contents of the file will be stored inside the p.log at '<branch-key-path>/data'. When
        /// not specified, or false, only the CID of the file is stored at '<branch-key-path>/cid'.
        ///
        /// The last three parameters specify the target codec, the hash codec and hash length used
        /// when generating the CID for the file. When not specified, the default target codec is
        /// 'identity' (i.g. raw bytes), the default hash codec is 'blake3' and the default hash
        /// length is '256'.
        ///
        /// <branch-key-path>:<file>[:<inline>:<target codec>:<hash codec>:<hash length in bits>].
        ///
        /// Examples:
        ///     '/myfile/:myphoto.jpg'
        ///     '/epoch/:./data/model.pth:::sha2:256'
        #[structopt(long = "file-op")]
        file_ops: Vec<String>,

        /// The parameters for VLAD generation.
        ///
        /// Values are made up of one to four fields separated by colons.  The last three are
        /// optional. If the signing codec is not specified, 'eddsa' is used. If the hashing codec
        /// is not specified, 'blake3' is used and if the hash length isn't specified, '256' is
        /// used.
        ///
        /// <first lock script path>[:<signing key codec>:<cid hashing codec>[:<hash length in bits>]]
        ///
        /// The signing codec can be one of: 'eddsa', 'es256k', 'blsg1', 'blsg2', 'lamport'.
        /// The cid hashing codec can be one of: 'blake2b', 'blake2s', 'blake3', 'sha2', 'sha3'
        /// The hash length can be one of: '256', '384', '512'
        ///
        /// Examples:
        ///     './first_lock.wasm:es256k:sha3'
        ///     './first_lock.wat:eddsa:sha2:256'
        #[structopt(long = "vlad")]
        vlad_params: String,

        /// The parameters for the entry signing key generation.
        ///
        /// The value can be one of: 'eddsa', 'es256k', 'blsg1', 'blsg2', 'lamport'.
        ///
        /// If not specified, 'eddsa' is used.
        #[structopt(long = "entry-key", default_value = "eddsa")]
        entry_key_codec: String,

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

    /// Print the plog information
    #[structopt(name = "print")]
    Print {
        /// The plog to verify and print
        #[structopt(parse(from_os_str))]
        input: Option<PathBuf>,
    },

    /// Update a provenance log with a new event
    #[structopt(name = "update")]
    Update {
        /// The parameters for delete ops. This may be used multiple times, as needed.
        ///
        /// Values are only a single field, the key-path that is to be deleted. If the key-path is
        /// a branch then all descendants of the branch will be deleted as well.
        ///
        /// <key-path>
        ///
        /// Examples:
        ///     '/emailkey'
        ///     '/github_endpoint'
        #[structopt(long = "delete-op")]
        delete_ops: Vec<String>,

        /// The parameters for key generation and advertisement. This may be used multiple times,
        /// as needed.
        ///
        /// Values are made up of two to five fields separated by colons, the last three fields are
        /// optional. The threshold and limit values are for when you want to create a threshold
        /// signature group and publish the public key. The revoke field is a boolean that
        /// determines if revocation should be signaled by first deleting the key path before
        /// setting a new key.
        ///
        /// <key-path>:<key codec>[:<threshold>:<limit>:<revoke>]
        ///
        /// Examples:
        ///     '/emailkey:eddsa'
        ///     '/recoverykey:lamport:3:5'
        #[structopt(long = "key-op")]
        key_ops: Vec<String>,

        /// The parameters for storing strings in the p.log. This is useful for storing textual
        /// data such as meta data, endoint URLs, peer IDs, multiaddrs, whatever. This may be used
        /// multiple times, as needed.
        ///
        /// Values are made up of two fields separated by colons.
        ///
        /// <key-path>:<string>
        ///
        /// Examples:
        ///     '/contact/email:dwg@linuxprogrammer.org'
        ///     '/contact/name:Dave Grantham'
        ///     '/contact/telegram: @dwgrantham'
        #[structopt(long = "string-op")]
        string_ops: Vec<String>,

        /// The parameters for storing/reference files in the p.log. This is most useful for
        /// tracking the provenance of data in external files. This may be used multiple times, as
        /// needed.
        ///
        /// Values are made up of two to six fields, the last four are optional. The 'inline'
        /// field is either 'true' or 'false' with the default being 'false'. When true, the
        /// contents of the file will be stored inside the p.log at '<branch-key-path>/data'. When
        /// not specified, or false, only the CID of the file is stored at '<branch-key-path>/cid'.
        ///
        /// The last three parameters specify the target codec, the hash codec and hash length used
        /// when generating the CID for the file. When not specified, the default target codec is
        /// 'identity' (i.g. raw bytes), the default hash codec is 'blake3' and the default hash
        /// length is '256'.
        ///
        /// <branch-key-path>:<file>[:<inline>:<target codec>:<hash codec>:<hash length in bits>].
        ///
        /// Examples:
        ///     '/myfile/:myphoto.jpg'
        ///     '/epoch/:./data/model.pth:::sha2:256'
        #[structopt(long = "file-op")]
        file_ops: Vec<String>,

        /// The lock script for verifying the next entry.
        #[structopt(long = "lock", parse(from_os_str))]
        lock_script_path: PathBuf,

        /// The unlock script for providing proof for the first lock script.
        #[structopt(long = "unlock", parse(from_os_str))]
        unlock_script_path: PathBuf,

        /// The key to use for signing the new entry
        #[structopt(long = "entry-signing-key", parse(from_os_str))]
        entry_signing_key: PathBuf,

        /// The output file to write the log to
        #[structopt(short = "o", parse(from_os_str))]
        output: Option<PathBuf>,

        /// The plog to verify and print
        #[structopt(parse(from_os_str))]
        input: Option<PathBuf>,
    },
}
