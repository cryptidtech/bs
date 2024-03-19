// SPDX-License-Identifier: FSL-1.1
use crate::{initialize_local_file, Error, Keychain};
use log::debug;
use multibase::Base;
use multicodec::Codec;
use multihash::EncodedMultihash;
use multikey::{Multikey, Views};
use multisig::Multisig;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, convert::TryFrom, fs::File, path::PathBuf};

const KEY_FILE: &'static str = "keyfile.json";
const ORG_DIRS: &'static [&'static str; 3] = &["tech", "cryptid", "bettersign"];

/// Keychain struct
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LocalFile {
    /// Map of private keys in the keychain
    keys: BTreeMap<EncodedMultihash, Multikey>,
    /// The path to the keyfile
    #[serde(skip)]
    path: PathBuf,
}

impl LocalFile {
    /// initialize a new default keyfile
    pub fn initialize(path: &PathBuf) -> Result<(), Error> {
        debug!("creating default keyfile: {}", path.display());
        let keyfile = LocalFile::default();
        let f = File::create(&path)?;
        serde_json::to_writer_pretty(f, &keyfile)?;
        Ok(())
    }
    /// try to load the keychain from disk
    pub fn try_load(path: &PathBuf) -> Result<Self, Error> {
        debug!("loading keyfile: {}", path.display());
        let f = File::options().read(true).write(false).open(&path)?;
        let mut lf: LocalFile = serde_json::from_reader(f)?;
        lf.path = path.clone();
        Ok(lf)
    }
    /// save the file keychain to disk
    pub fn save(&self) -> Result<(), Error> {
        let f = File::options().read(false).write(true).open(&self.path)?;
        debug!("saving keyfile: {}", self.path.display());
        serde_json::to_writer_pretty(f, self)?;
        Ok(())
    }
}

impl TryFrom<Option<PathBuf>> for LocalFile {
    type Error = Error;

    fn try_from(path: Option<PathBuf>) -> Result<Self, Self::Error> {
        //initialize the bettersign config file if needed
        let keyfile_path =
            initialize_local_file(path, ORG_DIRS, KEY_FILE, |pb| LocalFile::initialize(&pb))?;

        Ok(LocalFile::try_load(&keyfile_path)?)
    }
}

/// Interface to the keychain
impl Keychain for LocalFile {
    fn list(&self) -> Result<Vec<Multikey>, Error> {
        let mut keys = Vec::with_capacity(self.keys.len());
        for k in self.keys.values() {
            keys.push(k.clone())
        }
        Ok(keys)
    }

    fn get(&self, fingerprint: &EncodedMultihash) -> Result<Multikey, Error> {
        debug!("looking for: {}", fingerprint);
        for h in self.keys.keys() {
            debug!("checking: {}", h);
        }
        match self.keys.get(&fingerprint) {
            Some(k) => Ok(k.clone()),
            None => Err(Error::NoKey(fingerprint.to_string())),
        }
    }

    fn add(&mut self, key: &Multikey) -> Result<(), Error> {
        let kh = {
            let fv = key.fingerprint_view()?;
            EncodedMultihash::new(Base::Base58Btc, fv.fingerprint(Codec::Blake2S256)?)
        };
        self.keys.insert(kh, key.clone());
        self.save()?;
        Ok(())
    }

    fn sign(
        &mut self,
        key: &Multikey,
        combined: bool,
        _msg_encoding: Codec,
        msg: &[u8],
    ) -> Result<Multisig, Error> {
        let sv = key.sign_view()?;
        Ok(sv.sign(msg, combined, None)?)
    }
}
