// SPDX-License-Identifier: FSL-1.1
use multicodec::Codec;
use std::path::{Path, PathBuf};

/// the configuration for opening a new provenance log
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// the vlad key codec
    pub vladkey_codec: Option<Codec>,

    /// the entry key codec
    pub entrykey_codec: Option<Codec>,

    /// pubkey codec
    pub pubkey_codec: Option<Codec>,

    /// the vlad cid hash codec
    pub vlad_cid_hash_codec: Option<Codec>,

    /// first lock script
    pub first_lock_script: Option<PathBuf>,

    /// entry lock script
    pub entry_lock_script: Option<PathBuf>,
    
    /// entry unlock script
    pub entry_unlock_script: Option<PathBuf>,
}

impl Config {
    /// add the vladkey codec
    pub fn with_vladkey_codec(mut self, codec: Codec) -> Self {
        self.vladkey_codec = Some(codec);
        self
    }

    /// add the entrykey codec
    pub fn with_entrykey_codec(mut self, codec: Codec) -> Self {
        self.entrykey_codec = Some(codec);
        self
    }

    /// add the pubkey codec
    pub fn with_pubkey_codec(mut self, codec: Codec) -> Self {
        self.pubkey_codec = Some(codec);
        self
    }

    /// add vlad cid hash codec
    pub fn with_vlad_cid_hash_codec(mut self, codec: Codec) -> Self {
        self.vlad_cid_hash_codec = Some(codec);
        self
    }

    /// add in the first lock script
    pub fn with_first_lock_script<P: AsRef<Path>>(mut self, path: &P) -> Self {
        self.first_lock_script = Some(path.as_ref().to_path_buf());
        self
    }

    /// add the entry lock script
    pub fn with_entry_lock_script<P: AsRef<Path>>(mut self, path: &P) -> Self {
        self.entry_lock_script = Some(path.as_ref().to_path_buf());
        self
    }

    /// add in the entry unlock script
    pub fn with_entry_unlock_script<P: AsRef<Path>>(mut self, path: &P) -> Self {
        self.entry_unlock_script = Some(path.as_ref().to_path_buf());
        self
    }
}
