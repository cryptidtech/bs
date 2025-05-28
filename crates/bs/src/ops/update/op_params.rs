// SPDX-License-Identifier: FSL-1.1

use multicid::Cid;
use multicodec::Codec;
use multikey::Multikey;
use provenance_log::Key;

/// The Op params for additional ops
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OpParams {
    /// Noop params
    Noop {
        /// Key-path for Noop
        key: Key,
    },

    /// Delete op param
    Delete {
        /// Key-path for Delete
        key: Key,
    },

    /// For generating a new hash
    CidGen {
        /// Key-path branch for storing the cid and data under
        key: Key,
        /// the CID version
        version: Codec,
        /// the CID target codec
        target: Codec,
        /// the hashing codec
        hash: Codec,
        /// whether store the file data inside the p.log
        inline: bool,
        /// The Data save in the content address
        data: Vec<u8>,
    },

    /// For generating a new key
    KeyGen {
        /// key-path to store the generated key under
        key: Key,
        /// the key codec
        codec: Codec,
        /// the threshold for threshold key splitting
        threshold: usize,
        /// the limit for threshold key splitting
        limit: usize,
        /// the previous key should be explicitly deleted
        revoke: bool,
    },

    /// For using an existing CID
    UseCid {
        /// the key-path to store the cid under
        key: Key,
        /// the cid value to store
        cid: Cid,
    },

    /// For using a generated key
    UseKey {
        /// the key-path to store the key under
        key: Key,
        /// the key data to store
        mk: Multikey,
    },

    /// For using a string
    UseStr {
        /// the key-path to store the string under
        key: Key,
        /// the string data to store
        s: String,
    },

    /// For using binary data
    UseBin {
        /// the key-path to store the data under
        key: Key,
        /// the data to store
        data: Vec<u8>,
    },
}

impl Default for OpParams {
    fn default() -> Self {
        Self::Noop {
            key: Key::default(),
        }
    }
}
