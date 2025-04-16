// SPDX-License-Identifier: FSL-1.1
use crate::{error::EntryError, Error, Key, Lipmaa, Op, Script, Value};
use core::fmt;
use multibase::Base;
use multicid::{cid, Cid, EncodedCid, Vlad};
use multicodec::Codec;
use multihash::mh;
use multitrait::{Null, TryDecodeFrom};
use multiutil::{BaseEncoded, CodecInfo, EncodingInfo, Varbytes, Varuint};
use std::{convert::From, cmp::Ordering};

/// the multicodec sigil for a provenance entry
pub const SIGIL: Codec = Codec::ProvenanceLogEntry;

/// the current version of provenance entries this supports
pub const ENTRY_VERSION: u64 = 1;

/// the list of keys for the fields in an entry
pub const ENTRY_FIELDS: &[&str] = &[
    "/entry/",
    "/entry/verions",
    "/entry/vlad",
    "/entry/prev",
    "/entry/lipmaa",
    "/entry/seqno",
    "/entry/ops",
    "/entry/unlock",
    "/entry/proof",
];

/// a base encoded provenance entry
pub type EncodedEntry = BaseEncoded<Entry>;

/// An Entry represents a single state change associated with a key/value pair
/// in a provenance log.
#[derive(Clone, Eq, PartialEq)]
pub struct Entry {
    /// the entry version
    pub(crate) version: u64,
    /// long lived address for this provenance log
    pub(crate) vlad: Vlad,
    /// link to the previous entry
    pub(crate) prev: Cid,
    /// lipmaa link provides O(log n) traversal between entries
    pub(crate) lipmaa: Cid,
    /// sequence numbering of entries
    pub(crate) seqno: u64,
    /// operations on the namespace in this entry
    pub(crate) ops: Vec<Op>,
    /// the lock scripts associated with keys
    pub(crate) locks: Vec<Script>,
    /// the script that unlocks this entry, must include all fields except itself
    pub(crate) unlock: Script,
    /// the proof that this entry is valid, this can be a digital signature of
    /// some kind or a zkp or hash preimage. it is the proof data referenced by
    /// the unlock script and required by the lock script in the previous
    /// Entry. this data is generated using the Entry Builder by passing a
    /// closure to the `try_build` function that gets called with the complete
    /// serialized Entry to generate this data.
    pub(crate) proof: Vec<u8>,
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.seqno.cmp(&other.seqno)
    }
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl CodecInfo for Entry {
    /// Return that we are a ProvenanceEntry object
    fn preferred_codec() -> Codec {
        SIGIL
    }

    /// Return the same
    fn codec(&self) -> Codec {
        Self::preferred_codec()
    }
}

impl EncodingInfo for Entry {
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl wacc::Pairs for Entry {
    fn get(&self, key: &str) -> Option<wacc::Value> {
        let key = match Key::try_from(key) {
            Ok(key) => key,
            Err(_) => return None,
        };
        match self.get_value(&key) {
            Some(value) => {
                match value {
                    Value::Data(data) => Some(wacc::Value::Bin{ hint: key.to_string(), data }),
                    Value::Str(s) => Some(wacc::Value::Str{ hint: key.to_string(), data: s }),
                    Value::Nil => None,
                }
            },
            None => None,
        }
    }

    fn put(&mut self, _key: &str, _value: &wacc::Value) -> Option<wacc::Value> {
        None
    }
}

impl From<Entry> for Vec<u8> {
    fn from(val: Entry) -> Self {
        let mut v = Vec::default();
        // add in the entry sigil
        v.append(&mut SIGIL.into());
        // add in the version
        v.append(&mut Varuint(val.version).into());
        // add in the vlad
        v.append(&mut val.vlad.clone().into());
        // add in the prev link
        v.append(&mut val.prev.clone().into());
        // add in the lipmaa link
        v.append(&mut val.lipmaa.clone().into());
        // add in the seqno
        v.append(&mut Varuint(val.seqno).into());
        // add in the number of ops
        v.append(&mut Varuint(val.ops.len()).into());
        // add in the ops
        val.ops
            .iter()
            .for_each(|op| v.append(&mut op.clone().into()));
        // first add the number of keys
        v.append(&mut Varuint(val.locks.len()).into());
        // add in the locks
        val.locks
            .iter()
            .for_each(|script| v.append(&mut script.clone().into()));
        // add in the unlock script
        v.append(&mut val.unlock.clone().into());
        // add in the proof
        v.append(&mut Varbytes(val.proof.clone()).into());
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for Entry {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (pe, _) = Self::try_decode_from(bytes)?;
        Ok(pe)
    }
}

impl<'a> TryDecodeFrom<'a> for Entry {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the sigil
        let (sigil, ptr) = Codec::try_decode_from(bytes)?;
        if sigil != SIGIL {
            return Err(EntryError::MissingSigil.into());
        }
        // decode the version
        let (version, ptr) = Varuint::<u64>::try_decode_from(ptr)?;
        let version = version.to_inner();
        if version != ENTRY_VERSION {
            return Err(EntryError::InvalidVersion(1).into());
        }
        // decode the vlad
        let (vlad, ptr) = Vlad::try_decode_from(ptr)?;
        // decode the prev cid
        let (prev, ptr) = Cid::try_decode_from(ptr)?;
        // decode the lipmaa cid
        let (lipmaa, ptr) = Cid::try_decode_from(ptr)?;
        // decode the seqno
        let (seqno, ptr) = Varuint::<u64>::try_decode_from(ptr)?;
        let seqno = seqno.to_inner();
        // decode the number of ops
        let (num_ops, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        // decode the ops
        let (ops, ptr) = match *num_ops {
            0 => (Vec::default(), ptr),
            _ => {
                let mut ops = Vec::with_capacity(*num_ops);
                let mut p = ptr;
                for _ in 0..*num_ops {
                    let (op, ptr) = Op::try_decode_from(p)?;
                    ops.push(op);
                    p = ptr;
                }
                (ops, p)
            }
        };
        // decode the number of lock scripts
        let (num_locks, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        // decode the ops
        let (locks, ptr) = match *num_locks {
            0 => (Vec::default(), ptr),
            _ => {
                let mut locks = Vec::with_capacity(*num_locks);
                let mut p = ptr;
                for _ in 0..*num_locks {
                    let (lock, ptr) = Script::try_decode_from(p)?;
                    locks.push(lock);
                    p = ptr;
                }
                (locks, p)
            }
        };
        // decode the unlock script
        let (unlock, ptr) = Script::try_decode_from(ptr)?;
        // decode the proof
        let (proof, ptr) = Varbytes::try_decode_from(ptr)?;
        let proof = proof.to_inner();

        Ok((
            Self {
                version,
                vlad,
                prev,
                lipmaa,
                seqno,
                ops,
                locks,
                unlock,
                proof,
            },
            ptr,
        ))
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} - #{}\n\t{}\n\t{}",
            SIGIL,
            self.seqno,
            EncodedCid::new(Base::Base32Lower, self.cid()),
            EncodedCid::new(Base::Base32Lower, self.prev())
        )
    }
}

impl Default for Entry {
    fn default() -> Self {
        Builder::default()
            .with_vlad(&Vlad::default())
            .with_seqno(0)
            .with_unlock(&Script::default())
            .try_build(|_| Ok(Vec::default()))
            .unwrap()
    }
}

struct Iter<'a> {
    iter: std::slice::Iter<'static, &'static str>,
    entry: &'a Entry,
}

impl Iterator for Iter<'_> {
    type Item = (Key, Value);

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(k) => {
                let key = match Key::try_from(*k) {
                    Ok(key) => key,
                    Err(_) => return None,
                };
                self.entry.get_value(&key).map(|value| (key, value))
            }
            None => None
        }
    }
}

impl Entry {
    /// get an iterator over the keys and values
    pub fn iter(&self) -> impl Iterator<Item = (Key, Value)> + '_ {
        Iter {
            iter: ENTRY_FIELDS.iter(),
            entry: self
        }
    }

    /// get the Entry's values by Key
    pub fn get_value(&self, key: &Key) -> Option<Value> {
        match key.as_str() {
            "/entry/" => {
                let mut e = self.clone();
                e.proof = Vec::default();
                Some(Value::Data(e.into()))
            }
            "/entry/version" => Some(Value::Data(Varuint(self.version).into())),
            "/entry/vlad" => Some(Value::Data(self.vlad.clone().into())),
            "/entry/prev" => Some(Value::Data(self.prev.clone().into())),
            "/entry/lipmaa" => Some(Value::Data(self.lipmaa.clone().into())),
            "/entry/seqno" => Some(Value::Data(Varuint(self.seqno).into())),
            "/entry/ops" => {
                let mut v = Vec::new();
                v.append(&mut Varuint(self.ops.len()).into());
                self.ops
                    .iter()
                    .for_each(|op| v.append(&mut op.clone().into()));
                Some(Value::Data(v))
            }
            // TODO: make this accessible via an iterator
            //"/entry/locks" => Some(Value::Data(self.locks.clone().into())),
            "/entry/unlock" => Some(Value::Data(self.unlock.clone().into())),
            "/entry/proof" => Some(Value::Data(self.proof.clone())),
            _ => None,
        }
    }

    /// Get the cid of the previous entry if there is one
    pub fn prev(&self) -> Cid {
        self.prev.clone()
    }

    /// Get the sequence number of the entry
    pub fn seqno(&self) -> u64 {
        self.seqno
    }

    /// Get the vlad for the whole p.log
    pub fn vlad(&self) -> Vlad {
        self.vlad.clone()
    }

    /// get an iterator over the operations in the entry
    pub fn ops(&self) -> impl Iterator<Item = &Op> {
        self.ops.iter()
    }

    /// get an iterator over the lock scripts 
    pub fn locks(&self) -> impl Iterator<Item = &Script> {
        self.locks.iter()
    }

    /// get the cid of this entry
    pub fn cid(&self) -> Cid {
        let v: Vec<u8> = self.clone().into();
        cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, v.as_slice())
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap()
    }

    /// get the longest common branch context from the ops
    pub fn context(&self) -> Key {
        if self.ops.is_empty() {
            Key::default()
        } else {
            // get the first branch
            let mut ctx = self.ops.first().unwrap().clone().path().branch();

            // got through the rest looking for the shortest one
            for k in self.ops.iter() {
                ctx = k.path().branch().longest_common_branch(&ctx);
            }
            ctx
        }
    }

    /// go through the lock script from the previous entry and sort them in order of execution for
    /// validating this Entry. This goes through the mutation operations in this Event, looking at
    /// at the path for each op and building the valid set of lock scripts that govern all of teh
    /// branches and leaves that are modified in the set of mutation operations.
    pub fn sort_locks(&self, locks: &[Script]) -> Result<Vec<Script>, Error> {
        // the order of these lock scripts must be preservied in the final list of lock scripts
        let locks_in = locks.to_owned();
        // this is the set of lock scripts that govern all of the ops in the order established by
        // the lock array passed into this function
        let mut locks_tmp: Vec<Script> = Vec::default();
        // if there aren't any mutation ops, then "touch" the root branch "/" to force the root
        // lock script to execute
        let mut ops = match self.ops.len() {
            0 => vec![Op::Noop(Key::try_from("/")?)],
            _ => self.ops.clone()
        };
        // if this entry changes the lock scripts from the previous entry then "touch" the root
        // branch "/" to force the root lock script to execute
        if locks_in != self.locks {
            ops.push(Op::Noop(Key::try_from("/")?));
        }

        // go through the set of mutation operations to figure out which lock scripts govern the
        // proposed mutations
        for op in ops {
            //println!("checking op {}", op.path());
            for lock in &locks_in {
                // if the lock is a leaf, then parent_of is true if the op path is teh same
                // if the lock is a branch, then parent_of is true if the other path is a child
                // of the branch
                if lock.path().parent_of(&op.path()) && !locks_tmp.contains(lock) {
                    //println!("adding lock {} because of op {}", lock.path(), op.path());
                    locks_tmp.push(lock.clone());
                }
            }
        } 

        // now that we have all of the locks that govern one or more of the ops, we need to go
        // through the locks_in and if each lock is in the locks_tmp, it gets added to the
        // locks_out so that the order in locks_in is preserved
        let mut locks_out: Vec<Script> = Vec::default();
        for lock in &locks_in {
            if locks_tmp.contains(lock) && !locks_out.contains(lock) {
                locks_out.push(lock.clone());
            }
        }
        // this puts the lock scripts in the order from root to leaf by their key-paths. this
        // is a stable sort that preserves ordering of locks that govern the same path.
        locks_out.sort();
        Ok(locks_out)
    }
}

/// Builder for Entry objects
#[derive(Clone)]
pub struct Builder {
    version: u64,
    vlad: Option<Vlad>,
    prev: Option<Cid>,
    lipmaa: Option<Cid>,
    seqno: Option<u64>,
    ops: Vec<Op>,
    locks: Vec<Script>,
    unlock: Option<Script>,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            version: ENTRY_VERSION,
            vlad: None,
            prev: None,
            lipmaa: None,
            seqno: None,
            ops: Vec::default(),
            locks: Vec::default(),
            unlock: None,
        }
    }
}

// this initializes a builder for the next entry after this one
impl From<&Entry> for Builder {
    fn from(entry: &Entry) -> Self {
        Self {
            version: ENTRY_VERSION,
            vlad: Some(entry.vlad()),
            prev: Some(entry.cid()),
            lipmaa: None,
            seqno: Some(entry.seqno() + 1),
            ops: Vec::default(),
            locks: entry.locks.clone(),
            unlock: None,
        }
    }
}

impl Builder {
    /// Set the Vlad
    pub fn with_vlad(mut self, vlad: &Vlad) -> Self {
        self.vlad = Some(vlad.clone());
        self
    }

    /// Set the prev Cid
    pub fn with_prev(mut self, cid: &Cid) -> Self {
        self.prev = Some(cid.clone());
        self
    }

    /// Set the sequence number
    pub fn with_seqno(mut self, seqno: u64) -> Self {
        self.seqno = Some(seqno);
        self
    }

    /// Set the lipmaa Cid
    pub fn with_lipmaa(mut self, lipmaa: &Cid) -> Self {
        self.lipmaa = Some(lipmaa.clone());
        self
    }

    /// Set the ops
    pub fn with_ops(mut self, ops: &[Op]) -> Self {
        ops.clone_into(&mut self.ops);
        self
    }

    /// Add an op
    pub fn add_op(mut self, op: &Op) -> Self {
        self.ops.push(op.clone());
        self
    }

    /// Set the lock scripts
    pub fn with_locks(mut self, locks: &[Script]) -> Self {
        locks.clone_into(&mut self.locks);
        self
    }

    /// Set the lock script
    pub fn add_lock(mut self, script: &Script) -> Self {
        self.locks.push(script.clone());
        self
    }

    /// Set the unlock script
    pub fn with_unlock(mut self, unlock: &Script) -> Self {
        self.unlock = Some(unlock.clone());
        self
    }

    /// Build the Entry from the provided data and then call the `gen_proof`
    /// closure to generate a lock script and proof
    pub fn try_build<F>(&self, mut gen_proof: F) -> Result<Entry, Error>
    where
        F: FnMut(&mut Entry) -> Result<Vec<u8>, Error>,
    {
        let version = self.version;
        let vlad = self.vlad.clone().ok_or(EntryError::MissingVlad)?;
        let prev = self.prev.clone().unwrap_or_else(Cid::null);
        let seqno = self.seqno.unwrap_or_default();
        let lipmaa = if seqno.is_lipmaa() {
            self.lipmaa.clone().ok_or(EntryError::MissingLipmaaLink)?
        } else {
            Cid::null()
        };
        let unlock = self.unlock.clone().ok_or(EntryError::MissingUnlockScript)?;

        // first construct an entry with every field except the proof
        let mut entry = Entry {
            version,
            vlad,
            prev,
            seqno,
            lipmaa,
            ops: self.ops.clone(),
            locks: self.locks.clone(),
            unlock,
            proof: Vec::default(),
        };

        // call the gen_proof closure to create and store the proof data
        entry.proof = gen_proof(&mut entry)?;

        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{script, Value};
    use multicid::vlad;
    use multikey::nonce;

    #[test]
    fn test_builder() {
        let vlad = Vlad::default();
        let script = Script::default();
        let op = Op::default();
        let entry = Builder::default()
            .with_vlad(&vlad)
            .with_unlock(&script)
            .add_op(&op)
            .add_op(&op)
            .add_op(&op)
            .try_build(|_| Ok(Vec::default()))
            .unwrap();

        assert_eq!(entry.seqno(), 0);
        for op in entry.ops() {
            assert_eq!(Op::default(), op.clone());
        }
        assert_eq!(format!("{}", entry.context()), "/".to_string());
    }

    #[test]
    fn test_builder_next() {
        let vlad = Vlad::default();
        let script = Script::default();
        let op = Op::default();
        let entry = Builder::default()
            .with_vlad(&vlad)
            .with_unlock(&script)
            .add_op(&op)
            .add_op(&op)
            .add_op(&op)
            .try_build(|_| Ok(Vec::default()))
            .unwrap();

        assert_eq!(entry.seqno(), 0);
        for op in entry.ops() {
            assert_eq!(Op::default(), op.clone());
        }
        assert_eq!(format!("{}", entry.context()), "/".to_string());

        let entry2 = Builder::from(&entry)
            .with_unlock(&script)
            .add_op(&op)
            .add_op(&op)
            .add_op(&op)
            .try_build(|_| Ok(Vec::default()))
            .unwrap();
        assert_eq!(entry2.seqno(), 1);
        for op in entry2.ops() {
            assert_eq!(Op::default(), op.clone());
        }
        assert_eq!(format!("{}", entry2.context()), "/".to_string());
    }

    #[test]
    fn test_entry_iter() {
        let vlad = Vlad::default();
        let script = Script::default();
        let op = Op::default();
        let entry = Builder::default()
            .with_vlad(&vlad)
            .with_unlock(&script)
            .add_op(&op)
            .add_op(&op)
            .add_op(&op)
            .try_build(|_| Ok(Vec::default()))
            .unwrap();

        assert_eq!(entry.seqno(), 0);
        for op in entry.ops() {
            assert_eq!(Op::default(), op.clone());
        }
        assert_eq!(format!("{}", entry.context()), "/".to_string());

        for (key, _value) in entry.iter() {
            assert!(ENTRY_FIELDS.contains(&key.as_str()));
        }
    }

    #[test]
    fn test_sort_locks_change_lock_order() {
        let vlad = Vlad::default();
        let script = Script::default();
        let cid1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice")
                .unwrap().try_build().unwrap()
            )
            .try_build()
            .unwrap();
        let cid2 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3256, b"move every zig")
                .unwrap().try_build().unwrap()
            )
            .try_build()
            .unwrap();
        let locks_in1: Vec<Script> = vec![
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build().unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build().unwrap(),
            script::Builder::from_code_cid(&cid2)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build().unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/foo").unwrap())
                .try_build().unwrap(),
        ];

        // these are the same as above just in a different order which is significant
        let locks_in2: Vec<Script> = vec![
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build().unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build().unwrap(),
            script::Builder::from_code_cid(&cid2)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build().unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/foo").unwrap())
                .try_build().unwrap(),
        ];

        let ops: Vec<Op> = vec![
            Op::Noop(Key::try_from("/foo").unwrap()),
            Op::Update(Key::try_from("/bar/baz").unwrap(), Value::default()),
            Op::Delete(Key::try_from("/bob/babe/boo").unwrap()),
        ];

        let entry = Builder::default()
            .with_vlad(&vlad)
            .with_unlock(&script)
            .with_locks(&locks_in2) // same locks, different order
            .with_ops(&ops)
            .try_build(|_| Ok(Vec::default()))
            .unwrap();

        // sorting/filtering the locks from the previous event. in this case they are the same
        // locks but in a different order.
        let locks_out = entry.sort_locks(&locks_in1).unwrap();
        assert_eq!(locks_out[0],
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build().unwrap());
    }

    #[test]
    fn test_sort_locks_no_ops() {
        let vlad = Vlad::default();
        let script = Script::default();
        let cid1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice")
                .unwrap().try_build().unwrap()
            )
            .try_build()
            .unwrap();
        let cid2 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3256, b"move every zig")
                .unwrap().try_build().unwrap()
            )
            .try_build()
            .unwrap();
        let locks_in: Vec<Script> = vec![
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build().unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build().unwrap(),
            script::Builder::from_code_cid(&cid2)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build().unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/foo").unwrap())
                .try_build().unwrap(),
        ];

        let ops: Vec<Op> = vec![
        ];

        let entry = Builder::default()
            .with_vlad(&vlad)
            .with_unlock(&script)
            .with_ops(&ops)
            .try_build(|_| Ok(Vec::default()))
            .unwrap();

        let locks_out = entry.sort_locks(&locks_in).unwrap();
        assert_eq!(locks_out,
            vec![
                script::Builder::from_code_cid(&cid1)
                    .with_path(&Key::default())
                    .try_build().unwrap(),
            ]);
    }

    #[test]
    fn test_sort_locks() {
        let vlad = Vlad::default();
        let script = Script::default();
        let cid1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice")
                .unwrap().try_build().unwrap()
            )
            .try_build()
            .unwrap();
        let cid2 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3256, b"move every zig")
                .unwrap().try_build().unwrap()
            )
            .try_build()
            .unwrap();
        let locks_in: Vec<Script> = vec![
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build().unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build().unwrap(),
            script::Builder::from_code_cid(&cid2)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build().unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/foo").unwrap())
                .try_build().unwrap(),
        ];

        let ops: Vec<Op> = vec![
            Op::Noop(Key::try_from("/foo").unwrap()),
            Op::Update(Key::try_from("/bar/baz").unwrap(), Value::default()),
            Op::Delete(Key::try_from("/bob/babe/boo").unwrap()),
        ];

        let entry = Builder::default()
            .with_vlad(&vlad)
            .with_unlock(&script)
            .with_ops(&ops)
            .try_build(|_| Ok(Vec::default()))
            .unwrap();

        let locks_out = entry.sort_locks(&locks_in).unwrap();
        assert_eq!(locks_out[0],
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build().unwrap(),
        );
        assert_eq!(locks_out[1],
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build().unwrap()
        );
        assert_eq!(locks_out[2],
            script::Builder::from_code_cid(&cid2)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build().unwrap(),
        );

        assert_eq!(locks_out[3],
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/foo").unwrap())
                .try_build().unwrap(),
        );
    }
    #[test]
    fn test_preimage() {
        // build a nonce
        let bytes = hex::decode("d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832")
            .unwrap();
        let nonce = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

        // build a cid
        let cid = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let vlad = vlad::Builder::default()
            .with_nonce(&nonce)
            .with_cid(&cid)
            .try_build()
            .unwrap();

        let script = Script::Cid(Key::default(), cid);
        let op = Op::Update("/move".try_into().unwrap(), Value::Str("zig!".into()));
        let entry = Builder::default()
            .with_vlad(&vlad)
            .add_lock(&script)
            .with_unlock(&script)
            .add_op(&op)
            .try_build(|e| Ok(e.vlad.clone().into()))
            .unwrap();

        assert_eq!(entry.seqno(), 0);
        for op in entry.ops() {
            assert_eq!(
                Op::Update("/move".try_into().unwrap(), Value::Str("zig!".into())),
                op.clone()
            );
        }
        //println!("preimage entry: {}", hex::encode(&entry.proof));
        assert_eq!(entry.proof, hex::decode("8724bb2420d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832017114405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be").unwrap());
        assert_eq!(format!("{}", entry.context()), "/".to_string());
    }
}

/*
in wild's embrace, hearts find their rest,
nature's gifts, for the loving, are best.
in every leaf, in each bird's song,
the wilderness, where souls belong.
*/
