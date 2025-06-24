// SPDX-License-Identifier: FSL-1.1
//! # Provenance Log Entry
//!
//! This module implements the core `Entry` data structure for provenance logs.
//! An `Entry` represents a single state change in a provenance log, containing
//! operations that modify key-value pairs, along with authentication information.
//!
//! Entries are linked together to form a chain, with each entry containing:
//! - References to previous entries (prev, lipmaa links)
//! - Operations that modify the state (updates, deletes, no-ops)
//! - Lock scripts that govern permissible operations on paths
//! - An unlock script and proof that authenticates the entry
//!
//! ## Usage Example
//!
//! ```
//! use provenance_log::{
//!     entry::{Entry, EntryBuilder},
//!     Key, Op, Script, Error, Value
//! };
//! use multicid::{Cid, Vlad};
//! use multicodec::Codec;
//! use multihash::mh;
//! use multikey::{EncodedMultikey, Multikey, Views};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create or load a signing key
//! let signing_key = EncodedMultikey::try_from(
//!     "fba2480260874657374206b6579010120cbd87095dc5863fcec46a66a1d4040a73cb329f92615e165096bd50541ee71c0"
//! )?;
//!
//! // Create a vlad (identifier for the provenance log)
//! let cid = Cid::default(); // In practice, use a meaningful CID
//! let vlad = Vlad::default(); // In practice, initialize with proper values
//!
//! // Create an unlock script that will be used for authentication
//! let unlock_script = Script::Code(
//!     Key::default(),
//!     r#"
//!         push("/entry/");
//!         push("/entry/proof");
//!     "#
//!     .to_string(),
//! );
//!
//! // Create a lock script that will govern access to paths
//! let lock_script = Script::Code(
//!     Key::default(),
//!     r#"
//!         check_signature("/pubkey", "/entry/")
//!     "#
//!     .to_string(),
//! );
//!
//! // Create operations to be included in the entry
//! let pubkey_op = Op::Update(
//!     "/pubkey".try_into()?,
//!     Value::Data(signing_key.conv_view()?.to_public_key()?.into())
//! );
//!
//! let data_op = Op::Update(
//!     "/data/example".try_into()?,
//!     Value::Str("Hello, provenance log!".into())
//! );
//!
//! // For the first entry in a log
//! let first_entry = Entry::builder()
//!     .vlad(vlad.clone())
//!     .seqno(0)
//!     .unlock(unlock_script.clone())
//!     .locks(vec![lock_script.clone()])
//!     .ops(vec![pubkey_op.clone()])
//!     .build();
//!
//! // Prepare the unsigned entry for signing
//! let unsigned_entry: Entry = first_entry.prepare_unsigned_entry()?;
//! let entry_bytes: Vec<u8> = unsigned_entry.clone().into();
//!
//! // Sign the entry with the signing key
//! let signature = {
//!     let sign_view = signing_key.sign_view()?;
//!     sign_view.sign(&entry_bytes, false, None)?
//! };
//!
//! // Finalize the entry with the signature as proof
//! let signed_first_entry: Entry = unsigned_entry.try_build_with_proof(signature.into())?;
//!
//! // For subsequent entries, build from the previous entry
//! let next_entry_builder= EntryBuilder::from(&signed_first_entry);
//! let next_entry = next_entry_builder
//!     .unlock(unlock_script)
//!     .build();
//!
//! // Add lock scripts if needed
//! let mut mutable_entry = next_entry;
//! mutable_entry.add_lock(&lock_script);
//!
//! // Add operations
//! mutable_entry.add_op(&data_op);
//! mutable_entry.add_op(&Op::Delete("/old/data".try_into()?));
//!
//! // Prepare for signing
//! let unsigned_entry = mutable_entry.prepare_unsigned_entry()?;
//! let entry_bytes: Vec<u8> = unsigned_entry.clone().into();
//!
//! // Sign the entry
//! let signature = {
//!     let sign_view = signing_key.sign_view()?;
//!     sign_view.sign(&entry_bytes, false, None)?
//! };
//!
//! // Finalize with signature
//! let finalized_entry = unsigned_entry.try_build_with_proof(signature.into())?;
//!
//! // The entry is now ready to be added to the provenance log
//! # Ok(())
//! # }
//! ```
//!
//! ## Entry Structure
//!
//! Each entry contains:
//! - `version`: The entry format version
//! - `vlad`: Long-lived address for this provenance log
//! - `prev`: Link to the previous entry
//! - `lipmaa`: Link providing O(log n) traversal between entries
//! - `seqno`: Sequence number for this entry
//! - `ops`: Operations on the namespace (updates, deletes, no-ops)
//! - `locks`: Lock scripts associated with keys
//! - `unlock`: Script that unlocks this entry
//! - `proof`: Authentication data (signature, hash preimage, etc.)
//!
//! ## Building Entries
//!
//! Entries are created using a builder pattern with two phases:
//! 1. Create an unsigned entry using `Entry::builder()` or `EntryBuilder::from(&prev_entry)`
//! 2. Finalize the entry with authentication using `prepare_unsigned_entry()` to create
//!  the bytes to be signed, followed by `try_build_with_proof()`.
//!
//! This two-phase approach allows for proper signature generation on the serialized form
//! of the unsigned entry.

mod fields;
pub use fields::Field;

use crate::{error::EntryError, Error, Key, Lipmaa, Op, Script, Value};
use core::fmt;
use multibase::Base;
use multicid::{cid, Cid, EncodedCid, Vlad};
use multicodec::Codec;
use multihash::mh;
use multitrait::{Null, TryDecodeFrom};
use multiutil::{BaseEncoded, CodecInfo, EncodingInfo, Varbytes, VarbytesIter, Varuint};
use std::{cmp::Ordering, convert::From};

/// the multicodec sigil for a provenance entry
pub const SIGIL: Codec = Codec::ProvenanceLogEntry;

/// the current version of provenance entries this supports
pub const ENTRY_VERSION: u64 = 1;

/// a base encoded provenance entry
pub type EncodedEntry = BaseEncoded<Entry>;

/// An Entry represents a single state change in a provenance log, containing
/// operations that modify key-value pairs, along with authentication information.
///
/// Entries are linked together to form a chain, with each entry containing
/// references to previous entries, operations that modify the state, and
/// cryptographic proof data that authenticates the entry.
///
/// # Fields
///
/// * `version` - Format version for this entry (defaults to `ENTRY_VERSION`)
/// * `vlad` - Virtual Long-lived ADdress that uniquely identifies this provenance log
/// * `prev` - CID link to the previous entry, establishing the chain
/// * `lipmaa` - CID link providing O(log n) traversal between entries
/// * `seqno` - Sequence number for tracking entry order and detecting forks
/// * `ops` - Ordered list of operations that modify the namespace (updates, deletes, no-ops)
/// * `locks` - Lock scripts that govern permissions for paths in the next entry
/// * `unlock` - Script that authenticates this entry against the previous entry's locks
/// * `proof` - Authentication data (signature, hash preimage, etc.) referenced by the unlock script
///
/// # Entry Building Process
///
/// Entries are created using a two-phase builder pattern:
/// 1. Create an unsigned entry using `Entry::builder()` or `EntryBuilder::from(&prev_entry)`
/// 2. Prepare for signing with `prepare_unsigned_entry()`, sign the serialized bytes, then
///    finalize with `try_build_with_proof()`
///
/// This approach ensures proper signature generation over the serialized form of the entry.
///
/// # Examples
///
/// See the module documentation for usage examples.
#[derive(bon::Builder, Clone, Eq, PartialEq)]
pub struct Entry {
    /// Format version for this entry, defaults to `ENTRY_VERSION`
    #[builder(default = ENTRY_VERSION)]
    pub(crate) version: u64,

    /// Verifiable Long-lived ADdress (VLAD) that uniquely identifies this provenance log
    /// across different storage systems.
    pub(crate) vlad: Vlad,

    /// CID link to the previous entry in the chain, defaults to `Cid::null()`
    /// for the first entry in a log.
    #[builder(default = Cid::null())]
    pub(crate) prev: Cid,

    /// Lipmaa link provides O(log n) traversal between entries, enabling efficient
    /// verification and navigation of the log. Defaults to `Cid::null()` for entries
    /// where a lipmaa link isn't applicable.
    #[builder(default = Cid::null())]
    pub(crate) lipmaa: Cid,

    /// Sequence number of this entry in the log, defaults to 0 for the first entry.
    /// Used for detecting forks and erasures in the log.
    #[builder(default = 0)]
    pub(crate) seqno: u64,

    /// Ordered list of operations that modify the namespace in this entry.
    /// The order of these operations is significant as they are applied sequentially.
    #[builder(default)]
    pub(crate) ops: Vec<Op>,

    /// Lock scripts associated with this entry, governing the paths in the entry.
    /// These scripts are organized from root to leaf by path and executed in this order
    /// when validating the next entry in the log.
    #[builder(default)]
    pub(crate) locks: Vec<Script>,

    /// Script that unlocks/authenticates this entry against the previous entry's locks.
    /// Must reference all fields except itself and the proof to enable validation.
    pub(crate) unlock: Script,

    /// Proof data that authenticates this entry, typically a digital signature or hash preimage.
    /// This data is referenced by the unlock script and validated against the lock scripts
    /// in the previous entry.
    #[builder(default)]
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

impl comrade::Pairs for &Entry {
    fn get(&self, key: &str) -> Option<comrade::Value> {
        let key = match Key::try_from(key) {
            Ok(key) => key,
            Err(_) => return None,
        };
        match self.get_value(&key) {
            Some(value) => match value {
                Value::Data(data) => Some(comrade::Value::Bin {
                    hint: key.to_string(),
                    data,
                }),
                Value::Str(s) => Some(comrade::Value::Str {
                    hint: key.to_string(),
                    data: s,
                }),
                Value::Nil => None,
            },
            None => None,
        }
    }

    fn put(&mut self, _key: &str, _value: &comrade::Value) -> Option<comrade::Value> {
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
        v.extend(&mut VarbytesIter::from(&val.proof));
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

struct Iter<'a> {
    field_idx: usize,
    entry: &'a Entry,
}

impl Iterator for Iter<'_> {
    type Item = (Key, Value);

    fn next(&mut self) -> Option<Self::Item> {
        if self.field_idx < Field::all().len() {
            let field = Field::all()[self.field_idx];
            self.field_idx += 1;

            let key = match Key::try_from(field.as_str()) {
                Ok(key) => key,
                Err(_) => return self.next(), // Skip this one and try the next
            };

            self.entry.get_value(&key).map(|value| (key, value))
        } else {
            None
        }
    }
}

impl Entry {
    /// get an iterator over the keys and values
    pub fn iter(&self) -> impl Iterator<Item = (Key, Value)> + '_ {
        Iter {
            field_idx: 0,
            entry: self,
        }
    }

    /// Get an [Entry]'s [Value] by [Key], either from
    /// a [Field] or from the [Op]s.
    pub fn get_value(&self, k: &Key) -> Option<Value> {
        match k.as_str() {
            Field::ENTRY => {
                let mut e = self.clone();
                e.proof = Vec::default();
                Some(Value::Data(e.into()))
            }
            Field::VERSION => Some(Value::Data(Varuint(self.version).into())),
            Field::VLAD => Some(Value::Data(self.vlad.clone().into())),
            Field::PREV => Some(Value::Data(self.prev.clone().into())),
            Field::LIPMAA => Some(Value::Data(self.lipmaa.clone().into())),
            Field::SEQNO => Some(Value::Data(Varuint(self.seqno).into())),
            Field::OPS => {
                let mut v = Vec::new();
                v.append(&mut Varuint(self.ops.len()).into());
                self.ops
                    .iter()
                    .for_each(|op| v.append(&mut op.clone().into()));
                Some(Value::Data(v))
            }
            Field::UNLOCK => Some(Value::Data(self.unlock.clone().into())),
            Field::PROOF => Some(Value::Data(self.proof.clone())),
            _ => self
                .ops()
                .find_map(|op| {
                    if let Op::Update(key, value) = op {
                        if key == k {
                            return Some(value);
                        }
                    }
                    None
                })
                .cloned(),
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
    pub fn vlad(&self) -> &Vlad {
        &self.vlad
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
            _ => self.ops.clone(),
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

impl Entry {
    /// Add an operation to the entry
    pub fn add_op(&mut self, op: &Op) {
        self.ops.push(op.clone());
    }

    /// Set the lipmaa Cid
    pub fn with_lipmaa(&mut self, lipmaa: &Cid) {
        self.lipmaa = lipmaa.clone();
    }

    #[allow(dead_code)]
    fn extend_ops<I>(&mut self, ops: I)
    where
        I: IntoIterator,
        I::Item: Into<Op>,
    {
        for op in ops {
            self.ops.push(op.into());
        }
    }

    /// Add an unlock [Script] to the entry
    pub fn add_lock(&mut self, script: &Script) {
        self.locks.push(script.clone());
    }

    /// Preapre an unsigned [Entry] with empty proof for signing
    pub fn prepare_unsigned_entry(self) -> Result<Entry, Error> {
        let version = self.version;
        let vlad = self.vlad.clone();
        let prev = self.prev.clone();
        let seqno = self.seqno;
        let lipmaa = if seqno.is_lipmaa() {
            self.lipmaa.clone()
        } else {
            Cid::null()
        };
        let unlock = self.unlock.clone();
        let ops = self.ops.clone();
        let locks = self.locks.clone();

        Ok(Entry {
            version,
            vlad,
            prev,
            seqno,
            lipmaa,
            ops,
            locks,
            unlock,
            proof: Vec::default(),
        })
    }

    /// Tries to apply the given proof to the entry and
    /// build the finalized entry with the provided proof
    pub fn try_build_with_proof(self, proof: Vec<u8>) -> Result<Entry, Error> {
        let mut entry = self.prepare_unsigned_entry()?;
        entry.proof = proof;
        Ok(entry)
    }

    /// Backward compatibility method that combines prepare and finalize
    /// This maintains the same interface for existing code
    #[deprecated(
        since = "1.1.0",
        note = "Please use prepare_unsigned_entry() then finalize_with_proof() instead"
    )]
    pub fn try_build<F>(self, gen_proof: F) -> Result<Entry, Error>
    where
        F: FnOnce(&Entry) -> Result<Vec<u8>, Error>,
    {
        let unsigned_entry = self.prepare_unsigned_entry()?;
        let proof = gen_proof(&unsigned_entry)?;
        unsigned_entry.try_build_with_proof(proof)
    }
}

// this initializes a builder for the next entry after this one
impl From<&Entry>
    for EntryBuilder<
        entry_builder::SetLocks<
            entry_builder::SetSeqno<
                entry_builder::SetPrev<entry_builder::SetVlad<entry_builder::SetVersion>>,
            >,
        >,
    >
{
    fn from(entry: &Entry) -> Self {
        Entry::builder()
            .version(ENTRY_VERSION)
            .vlad(entry.vlad().clone())
            .prev(entry.cid())
            .seqno(entry.seqno() + 1)
            .locks(entry.locks.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{script, Value};
    use multicid::vlad;
    use multikey::nonce;
    use test_log::test;
    use tracing::{span, Level};

    #[test]
    fn test_builder() {
        let _s = span!(Level::INFO, "test_builder").entered();
        let vlad = Vlad::default();
        let script = Script::default();
        let op = Op::default();
        let entry = Entry::builder()
            .vlad(vlad)
            .unlock(script)
            .ops(vec![op.clone(), op.clone(), op.clone()])
            .build();

        assert_eq!(entry.seqno(), 0);
        for op in entry.ops() {
            assert_eq!(Op::default(), op.clone());
        }
        assert_eq!(format!("{}", entry.context()), "/".to_string());
    }

    #[test]
    fn test_builder_next() {
        let _s = span!(Level::INFO, "test_builder_next").entered();
        let vlad = Vlad::default();
        let script = Script::default();
        let op = Op::default();
        let entry = Entry::builder()
            .vlad(vlad)
            .unlock(script.clone())
            .ops(vec![op.clone(), op.clone(), op.clone()])
            .build();

        assert_eq!(entry.seqno(), 0);
        for op in entry.ops() {
            assert_eq!(Op::default(), op.clone());
        }
        assert_eq!(format!("{}", entry.context()), "/".to_string());

        let entry2 = EntryBuilder::from(&entry)
            .unlock(script)
            .ops(vec![op.clone(), op.clone()])
            .build();
        assert_eq!(entry2.seqno(), 1);
        for op in entry2.ops() {
            assert_eq!(Op::default(), op.clone());
        }
        assert_eq!(format!("{}", entry2.context()), "/".to_string());
    }

    #[test]
    fn test_entry_iter() {
        let _s = span!(Level::INFO, "test_entry_iter").entered();
        let vlad = Vlad::default();
        let script = Script::default();
        let op = Op::default();
        let entry = Entry::builder()
            .vlad(vlad)
            .unlock(script.clone())
            .ops(vec![op.clone(), op.clone(), op.clone()])
            .build();

        assert_eq!(entry.seqno(), 0);
        for op in entry.ops() {
            assert_eq!(Op::default(), op.clone());
        }
        assert_eq!(format!("{}", entry.context()), "/".to_string());

        for (key, _value) in entry.iter() {
            assert!(Field::all_paths().contains(&key.as_str()));
        }
    }

    #[test]
    fn test_sort_locks_change_lock_order() {
        let _s = span!(Level::INFO, "test_sort_locks_change_lock_order").entered();
        let vlad = Vlad::default();
        let script = Script::default();
        let cid1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();
        let cid2 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3256, b"move every zig")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();
        let locks_in1: Vec<Script> = vec![
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid2)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/foo").unwrap())
                .try_build()
                .unwrap(),
        ];

        // these are the same as above just in a different order which is significant
        let locks_in2: Vec<Script> = vec![
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid2)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/foo").unwrap())
                .try_build()
                .unwrap(),
        ];

        let ops: Vec<Op> = vec![
            Op::Noop(Key::try_from("/foo").unwrap()),
            Op::Update(Key::try_from("/bar/baz").unwrap(), Value::default()),
            Op::Delete(Key::try_from("/bob/babe/boo").unwrap()),
        ];

        let entry = Entry::builder()
            .vlad(vlad)
            .unlock(script)
            .locks(locks_in2) // same locks, different order
            .ops(ops)
            .build();

        // sorting/filtering the locks from the previous event. in this case they are the same
        // locks but in a different order.
        let locks_out = entry.sort_locks(&locks_in1).unwrap();
        assert_eq!(
            locks_out[0],
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build()
                .unwrap()
        );
    }

    #[test]
    fn test_sort_locks_no_ops() {
        let _s = span!(Level::INFO, "test_sort_locks_no_ops").entered();
        let vlad = Vlad::default();
        let script = Script::default();
        let cid1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();
        let cid2 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3256, b"move every zig")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();
        let locks_in: Vec<Script> = vec![
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid2)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/foo").unwrap())
                .try_build()
                .unwrap(),
        ];

        let ops: Vec<Op> = vec![];

        let entry = Entry::builder().vlad(vlad).unlock(script).ops(ops).build();

        let locks_out = entry.sort_locks(&locks_in).unwrap();
        assert_eq!(
            locks_out,
            vec![script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build()
                .unwrap(),]
        );
    }

    #[test]
    fn test_sort_locks() {
        let _s = span!(Level::INFO, "test_sort_locks").entered();
        let vlad = Vlad::default();
        let script = Script::default();
        let cid1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();
        let cid2 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3256, b"move every zig")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();
        let locks_in: Vec<Script> = vec![
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid2)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/foo").unwrap())
                .try_build()
                .unwrap(),
        ];

        let ops: Vec<Op> = vec![
            Op::Noop(Key::try_from("/foo").unwrap()),
            Op::Update(Key::try_from("/bar/baz").unwrap(), Value::default()),
            Op::Delete(Key::try_from("/bob/babe/boo").unwrap()),
        ];

        let entry = Entry::builder().vlad(vlad).unlock(script).ops(ops).build();

        let locks_out = entry.sort_locks(&locks_in).unwrap();
        assert_eq!(
            locks_out[0],
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::default())
                .try_build()
                .unwrap(),
        );
        assert_eq!(
            locks_out[1],
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap()
        );
        assert_eq!(
            locks_out[2],
            script::Builder::from_code_cid(&cid2)
                .with_path(&Key::try_from("/bar/").unwrap())
                .try_build()
                .unwrap(),
        );

        assert_eq!(
            locks_out[3],
            script::Builder::from_code_cid(&cid1)
                .with_path(&Key::try_from("/foo").unwrap())
                .try_build()
                .unwrap(),
        );
    }

    #[test]
    fn test_preimage() {
        let _s = span!(Level::INFO, "test_preimage").entered();
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
            .try_build(|cid, _| {
                let v: Vec<u8> = cid.clone().into();
                Ok(v)
            })
            .unwrap();

        let script = Script::Cid(Key::default(), cid);
        let op = Op::Update("/move".try_into().unwrap(), Value::Str("zig!".into()));
        let mut entry = Entry::builder()
            .vlad(vlad)
            .locks(vec![script.clone()])
            .unlock(script)
            .build();
        entry.add_op(&op);

        #[allow(deprecated)]
        let entry = entry.try_build(|e| Ok(e.vlad.clone().into())).unwrap();

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
