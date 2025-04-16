// SPDX-License-Identifier: FSL-1.1
use crate::{error::ScriptError, Error, Key};
use core::fmt;
use multibase::Base;
use multicid::Cid;
use multicodec::Codec;
use multitrait::{EncodeInto, TryDecodeFrom};
use multiutil::{BaseEncoded, EncodingInfo, Varbytes};
use std::{cmp::Ordering, path::PathBuf};

/// the multicodec sigil for a provenance entry
pub const SIGIL: Codec = Codec::ProvenanceLogScript;

/// a base encoded provenance script
pub type EncodedScript = BaseEncoded<Script>;

/// the identifiers for the operations performed on the namespace in each entry
#[repr(u8)]
#[derive(Clone, Default, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub enum ScriptId {
    /// compiled binary script
    #[default]
    Bin,
    /// uncompiled script code
    Code,
    /// a cid referencing the script data
    Cid,
}

impl ScriptId {
    /// Get the numerical code for the operation id
    pub fn code(&self) -> u8 {
        self.clone().into()
    }

    /// convert the operation id to a str
    pub fn as_str(&self) -> &str {
        match self {
            Self::Bin => "bin",
            Self::Code => "code",
            Self::Cid => "cid",
        }
    }
}

impl From<ScriptId> for u8 {
    fn from(val: ScriptId) -> Self {
        val as u8
    }
}

impl From<&Script> for ScriptId {
    fn from(op: &Script) -> Self {
        match op {
            Script::Bin(_, _) => Self::Bin,
            Script::Code(_, _) => Self::Code,
            Script::Cid(_, _) => Self::Cid,
        }
    }
}

impl TryFrom<u8> for ScriptId {
    type Error = Error;

    fn try_from(c: u8) -> Result<Self, Self::Error> {
        match c {
            0 => Ok(Self::Bin),
            1 => Ok(Self::Code),
            2 => Ok(Self::Cid),
            _ => Err(ScriptError::InvalidScriptId(c).into()),
        }
    }
}

impl From<ScriptId> for Vec<u8> {
    fn from(val: ScriptId) -> Self {
        let v: u8 = val.into();
        v.encode_into()
    }
}

impl<'a> TryFrom<&'a [u8]> for ScriptId {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Error> {
        let (id, _) = Self::try_decode_from(bytes)?;
        Ok(id)
    }
}

impl<'a> TryDecodeFrom<'a> for ScriptId {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (code, ptr) = u8::try_decode_from(bytes)?;
        Ok((Self::try_from(code)?, ptr))
    }
}

impl TryFrom<&str> for ScriptId {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "bin" => Ok(Self::Bin),
            "code" => Ok(Self::Code),
            "cid" => Ok(Self::Cid),
            _ => Err(ScriptError::InvalidScriptName(s.to_string()).into()),
        }
    }
}

impl fmt::Debug for ScriptId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ('{}')", self.as_str(), self.code())
    }
}

/// A Script is either a binary blob, printable code, or a CID reference. These are the values
/// stored in the virtual namespace of the log.
#[derive(Clone, Eq, PartialEq)]
pub enum Script {
    /// A binary code value
    Bin(Key, Vec<u8>),
    /// A printable code value
    Code(Key, String),
    /// A CID reference to the script
    Cid(Key, Cid),
}

impl Script {
    /// returns the path the script is assigned to
    pub fn path(&self) -> Key {
        match self {
            Self::Bin(p, _) => p.clone(),
            Self::Code(p, _) => p.clone(),
            Self::Cid(p, _) => p.clone(),
        }
    }
}

impl Ord for Script {
    /// orders scripts by their paths
    fn cmp(&self, other: &Self) -> Ordering {
        self.path().cmp(&other.path())
    }
}

impl PartialOrd for Script {
    /// partial ord for script 
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.path().cmp(&other.path()))
    }
}

impl EncodingInfo for Script {
    /// Return the preferred string encoding
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    /// Same
    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl Default for Script {
    fn default() -> Self {
        Self::Bin(Key::default(), Vec::default())
    }
}

impl AsRef<[u8]> for Script {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Bin(_, v) => v.as_ref(),
            Self::Code(_, s) => s.as_bytes(),
            Self::Cid(_, _) => &[],
        }
    }
}

impl From<Script> for Vec<u8> {
    fn from(val: Script) -> Self {
        let mut v = Vec::default();
        // add in the entry sigil
        v.append(&mut SIGIL.into());
        // add in the operation
        v.append(&mut ScriptId::from(&val).into());
        match val {
            Script::Bin(p, b) => {
                // add in the path
                v.append(&mut p.into());
                // add in the compiled binary script
                v.append(&mut Varbytes(b.clone()).into());
                v
            }
            Script::Code(p, s) => {
                // add in the path
                v.append(&mut p.into());
                // add in the uncompiled script
                v.append(&mut Varbytes(s.as_bytes().to_vec()).into());
                v
            }
            Script::Cid(p, c) => {
                // add in the path
                v.append(&mut p.into());
                // add in the cid
                v.append(&mut c.clone().into());
                v
            }
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Script {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Error> {
        let (op, _) = Self::try_decode_from(bytes)?;
        Ok(op)
    }
}

impl<'a> TryDecodeFrom<'a> for Script {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the sigil
        let (sigil, ptr) = Codec::try_decode_from(bytes)?;
        if sigil != SIGIL {
            return Err(ScriptError::MissingSigil.into());
        }
        // decode the value id
        let (id, ptr) = ScriptId::try_decode_from(ptr)?;
        let (v, ptr) = match id {
            ScriptId::Bin => {
                let (k, ptr) = Key::try_decode_from(ptr)?;
                let (b, ptr) = Varbytes::try_decode_from(ptr)?;
                (Self::Bin(k, b.to_inner()), ptr)
            }
            ScriptId::Code => {
                let (k, ptr) = Key::try_decode_from(ptr)?;
                let (s, ptr) = Varbytes::try_decode_from(ptr)?;
                let s = String::from_utf8(s.to_inner())?;
                (Self::Code(k, s), ptr)
            }
            ScriptId::Cid => {
                let (k, ptr) = Key::try_decode_from(ptr)?;
                let (c, ptr) = Cid::try_decode_from(ptr)?;
                (Self::Cid(k, c), ptr)
            }
        };
        Ok((v, ptr))
    }
}

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let id = ScriptId::from(self);
        match self {
            Self::Bin(k, b) => write!(f, "{:?} - {:?} - {:?}", id, k, Varbytes(b.clone())),
            Self::Code(k, s) => write!(f, "{:?} - {:?} -\n{}", id, k, s),
            Self::Cid(k, c) => write!(f, "{:?} - {:?} - {:?}", id, k, c),
        }
    }
}

/// Builder for Scripts that helps create them from files and Cid's
#[derive(Clone, Default)]
pub struct Builder {
    path: Option<Key>,
    bin: Option<PathBuf>,
    code: Option<PathBuf>,
    cid: Option<Cid>,
}

impl Builder {
    /// create a builder from the contents of a compile binary file
    pub fn from_bin_file(pb: &PathBuf) -> Self {
        Self {
            bin: Some(pb.to_owned()),
            ..Default::default()
        }
    }

    /// create a builder from the contents of uncompiled script code
    pub fn from_code_file(pb: &PathBuf) -> Self {
        Self {
            code: Some(pb.to_owned()),
            ..Default::default()
        }
    }

    /// create a builder from the contents of uncompiled script code
    pub fn from_code_cid(cid: &Cid) -> Self {
        Self {
            cid: Some(cid.clone()),
            ..Default::default()
        }
    }

    /// add the path which this path is assigned
    pub fn with_path(mut self, path: &Key) -> Self {
        self.path = Some(path.clone());
        self
    }

    /// Tries to build a Script from the collected data
    pub fn try_build(&self) -> Result<Script, Error> {
        let path = self.path.clone().unwrap_or_default();
        if let Some(b) = &self.bin {
            let b = std::fs::read(b).map_err(|e| ScriptError::LoadingFailed(e.to_string()))?;
            if b.len() < 4 {
                Err(ScriptError::MissingCode.into())
            } else if b[0] == 0x00 && b[1] == 0x61 && b[2] == 0x73 && b[3] == 0x6d {
                Ok(Script::Bin(path, b))
            } else {
                Err(ScriptError::InvalidScriptMagic.into())
            }
        } else if let Some(c) = &self.code {
            let c = std::fs::read(c).map_err(|e| ScriptError::LoadingFailed(e.to_string()))?;
            Ok(Script::Code(path, String::from_utf8(c)?))
        } else if let Some(cid) = &self.cid {
            // TODO: this is where we could handle resolving the Cid into either code or binary
            // script data. for now we're just going to pass it along for later processing
            Ok(Script::Cid(path, cid.clone()))
        } else {
            Err(ScriptError::BuildFailed.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sort_scripts() {
        let cid = Cid::default();
        let mut v: Vec<Script> = vec![
            Builder::from_code_cid(&cid).with_path(&Key::try_from("/bar/").unwrap()).try_build().unwrap(),
            Builder::from_code_cid(&cid).with_path(&Key::default()).try_build().unwrap(),
            Builder::from_code_cid(&cid).with_path(&Key::try_from("/bar/").unwrap()).try_build().unwrap(),
            Builder::from_code_cid(&cid).with_path(&Key::try_from("/foo").unwrap()).try_build().unwrap(),
        ];
        v.sort();
        for s in v {
            println!("{}: {:?}", s.path(), s);
        }
    }
}
