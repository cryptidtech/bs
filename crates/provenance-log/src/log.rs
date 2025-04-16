// SPDX-License-Identifier: FSL-1.1
use crate::{entry, error::LogError, Entry, Error, Kvp, Script, Stk};
use core::fmt;
use multibase::Base;
use multicid::{Cid, Vlad};
use multicodec::Codec;
use multitrait::{Null, TryDecodeFrom};
use multiutil::{BaseEncoded, CodecInfo, EncodingInfo, Varuint};
use std::collections::BTreeMap;
use wacc::{prelude::StoreLimitsBuilder, vm, Stack};

/// the multicodec provenance log codec
pub const SIGIL: Codec = Codec::ProvenanceLog;

/// the current version of provenance entries this supports
pub const LOG_VERSION: u64 = 1;

/// a base encoded provenance log
pub type EncodedLog = BaseEncoded<Log>;

/// the log entries type
pub type Entries = BTreeMap<Cid, Entry>;

/// A Provenance Log is made up of a series of Entry objects that are linked
/// together using content addressing links. Entry object also has a lipmaa
/// linking structure for efficient O(log n) traversal between any two Entry
/// object in the Log.
#[derive(Clone, Default, PartialEq)]
pub struct Log {
    /// The version of this log format
    pub version: u64,
    /// Every log has a vlad identifier
    pub vlad: Vlad,
    /// The lock script for the first entry
    pub first_lock: Script,
    /// The first entry in the log
    pub foot: Cid,
    /// The latest entry in the log
    pub head: Cid,
    /// Entry objects are stored in a hashmap indexed by their Cid
    pub entries: Entries,
}

impl CodecInfo for Log {
    /// Return that we are a Log object
    fn preferred_codec() -> Codec {
        entry::SIGIL
    }

    /// Return that we are a Log
    fn codec(&self) -> Codec {
        Self::preferred_codec()
    }
}

impl EncodingInfo for Log {
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl From<Log> for Vec<u8> {
    fn from(val: Log) -> Self {
        let mut v = Vec::default();
        // add in the provenance log sigil
        v.append(&mut SIGIL.into());
        // add in the version
        v.append(&mut Varuint(val.version).into());
        // add in the vlad
        v.append(&mut val.vlad.clone().into());
        // add in the lock script for the first entry
        v.append(&mut val.first_lock.clone().into());
        // add in the foot cid
        v.append(&mut val.foot.clone().into());
        // add in the head cid
        v.append(&mut val.head.clone().into());
        // add in the entry count
        v.append(&mut Varuint(val.entries.len()).into());
        // add in the entries
        val.entries.iter().for_each(|(cid, entry)| {
            v.append(&mut cid.clone().into());
            v.append(&mut entry.clone().into());
        });
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for Log {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (pl, _) = Self::try_decode_from(bytes)?;
        Ok(pl)
    }
}

impl<'a> TryDecodeFrom<'a> for Log {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the sigil
        let (sigil, ptr) = Codec::try_decode_from(bytes)?;
        if sigil != SIGIL {
            return Err(LogError::MissingSigil.into());
        }
        // decode the version
        let (version, ptr) = Varuint::<u64>::try_decode_from(ptr)?;
        let version = version.to_inner();
        // decode the vlad
        let (vlad, ptr) = Vlad::try_decode_from(ptr)?;
        // decode the lock script for the first entry
        let (first_lock, ptr) = Script::try_decode_from(ptr)?;
        // decode the foot cid
        let (foot, ptr) = Cid::try_decode_from(ptr)?;
        // decode the head cid if there is one
        let (head, ptr) = Cid::try_decode_from(ptr)?;
        // decode the number of entries
        let (num_entries, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        // decode the entries
        let (entries, ptr) = match *num_entries {
            0 => (Entries::default(), ptr),
            _ => {
                let mut entries = Entries::new();
                let mut p = ptr;
                for _ in 0..*num_entries {
                    let (cid, ptr) = Cid::try_decode_from(p)?;
                    let (entry, ptr) = Entry::try_decode_from(ptr)?;
                    if entries.insert(cid.clone(), entry).is_some() {
                        return Err(LogError::DuplicateEntry(cid).into());
                    }
                    p = ptr;
                }
                (entries, p)
            }
        };
        Ok((
            Self {
                version,
                vlad,
                first_lock,
                foot,
                head,
                entries,
            },
            ptr,
        ))
    }
}

impl fmt::Debug for Log {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} - {:?} - {:?} - {:?} - {:?} - Entries: {}",
            self.codec(),
            self.version,
            self.vlad,
            self.head,
            self.foot,
            self.entries.len()
        )
    }
}

struct EntryIter<'a> {
    entries: Vec<&'a Entry>,
    current: usize,
}

impl<'a> Iterator for EntryIter<'a> {
    type Item = &'a Entry;

    fn next(&mut self) -> Option<Self::Item> {
        match self.entries.get(self.current) {
            Some(e) => {
                self.current += 1;
                Some(e)
            }
            None => None,
        }
    }
}

struct VerifyIter<'a> {
    entries: Vec<&'a Entry>,
    seqno: usize,
    prev_seqno: usize,
    kvp: Kvp<'a>,
    lock_scripts: Vec<Script>,
    error: Option<Error>,
}

impl<'a> Iterator for VerifyIter<'a> {
    type Item = Result<(usize, Entry, Kvp<'a>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        //println!("iter::next({})", self.seqno);
        let entry = match self.entries.get(self.seqno) {
            Some(e) => *e,
            None => return None,
        };

        // this is the check count if successful
        let mut count = 0;

        // set up the stacks
        let mut pstack = Stk::default();
        let mut rstack = Stk::default();

        // check the seqno meet the criteria
        if self.seqno > 0 && self.seqno != self.prev_seqno + 1 {
            // set our index out of range
            self.seqno = self.entries.len();
            // set the error state
            self.error = Some(LogError::InvalidSeqno.into());
            return Some(Err(self.error.clone().unwrap()));
        }

        // 'unlock:
        let mut result = {
            // run the unlock script using the entry as the kvp to get the
            // stack in the vm::Context set up.
            let unlock_ctx = vm::Context {
                current: entry,  // limit the available data to just the entry
                proposed: entry, // limit the available data to just the entry
                pstack: &mut pstack,
                rstack: &mut rstack,
                check_count: 0,
                write_idx: 0,
                context: entry.context().to_string(),
                log: Vec::default(),
                limiter: StoreLimitsBuilder::new()
                    .memory_size(1 << 16)
                    .instances(2)
                    .memories(1)
                    .build(),
            };

            let mut instance = match vm::Builder::new()
                .with_context(unlock_ctx)
                .with_bytes(entry.unlock.clone())
                .try_build()
            {
                Ok(i) => i,
                Err(e) => {
                    // set our index out of range
                    self.seqno = self.entries.len();
                    self.error = Some(LogError::Wacc(e).into());
                    return Some(Err(self.error.clone().unwrap()));
                }
            };
            //print!("running unlock script from seqno: {}...", self.seqno);

            // run the unlock script
            if let Some(e) = instance.run("for_great_justice").err() {
                // set our index out of range
                self.seqno = self.entries.len();
                self.error = Some(LogError::Wacc(e).into());
                return Some(Err(self.error.clone().unwrap()));
            }

            //println!("SUCCEEDED!");

            true
        };

        /*
        println!("values:");
        println!("{:?}", pstack.clone());
        println!("return:");
        println!("{:?}", rstack.clone());
        */

        if !result {
            // set our index out of range
            self.seqno = self.entries.len();
            self.error = Some(
                LogError::VerifyFailed(format!(
                    "unlock script failed\nvalues:\n{:?}\nreturn:\n{:?}",
                    rstack, pstack
                ))
                .into(),
            );
            return Some(Err(self.error.clone().unwrap()));
        }

        /*
        // set the entry to look into for proof and message values
        if let Some(e) = self.kvp.set_entry(entry).err() {
            // set our index out of range
            self.seqno = self.entries.len();
            self.error = Some(LogError::KvpSetEntryFailed(e.to_string()).into());
            return Some(Err(self.error.clone().unwrap()));
        }
        */

        // if this is the first entry, then we need to apply the
        // mutation ops
        if self.seqno == 0 {
            //println!("applying kvp ops for seqno 0");
            if let Some(e) = self.kvp.apply_entry_ops(entry).err() {
                // set our index out of range
                self.seqno = self.entries.len();
                self.error = Some(LogError::UpdateKvpFailed(e.to_string()).into());
                return Some(Err(self.error.clone().unwrap()));
            }
        }

        // 'lock:
        result = false;

        // build the set of lock scripts to run in order from root to longest branch to leaf
        let locks = match entry.sort_locks(&self.lock_scripts) {
            Ok(l) => l,
            Err(e) => {
                // set our index out of range
                self.seqno = self.entries.len();
                self.error = Some(e);
                return Some(Err(self.error.clone().unwrap()));
            }
        };

        // run each of the lock scripts
        for lock in locks {
            // NOTE: clone the kvp and stacks each time
            let lock_kvp = self.kvp.clone();
            let mut lock_pstack = pstack.clone();
            let mut lock_rstack = rstack.clone();

            {
                let lock_ctx = vm::Context {
                    current: &lock_kvp,
                    proposed: entry,
                    pstack: &mut lock_pstack,
                    rstack: &mut lock_rstack,
                    check_count: 0,
                    write_idx: 0,
                    context: entry.context().to_string(), // set the branch path for branch()
                    log: Vec::default(),
                    limiter: StoreLimitsBuilder::new()
                        .memory_size(1 << 16)
                        .instances(2)
                        .memories(1)
                        .build(),
                };

                let mut instance = match vm::Builder::new()
                    .with_context(lock_ctx)
                    .with_bytes(lock.clone())
                    .try_build()
                {
                    Ok(i) => i,
                    Err(e) => {
                        // set our index out of range
                        self.seqno = self.entries.len();
                        self.error = Some(LogError::Wacc(e).into());
                        return Some(Err(self.error.clone().unwrap()));
                    }
                };
                //print!("running lock script from seqno: {}...", self.seqno);

                // run the unlock script
                if let Some(e) = instance.run("move_every_zig").err() {
                    // set our index out of range
                    self.seqno = self.entries.len();
                    self.error = Some(LogError::Wacc(e).into());
                    return Some(Err(self.error.clone().unwrap()));
                }

                //println!("SUCCEEDED!");
            }

            // break out of this loop as soon as a lock script succeeds
            if let Some(v) = lock_rstack.top() {
                match v {
                    vm::Value::Success(c) => {
                        count = c;
                        result = true;
                        break;
                    }
                    _ => result = false,
                }
            }
        }

        if result {
            // if the entry verifies, apply it's mutataions to the kvp
            // the 0th entry has already been applied at this point so no
            // need to do it here
            if self.seqno > 0 {
                if let Some(e) = self.kvp.apply_entry_ops(entry).err() {
                    // set our index out of range
                    self.seqno = self.entries.len();
                    self.error = Some(LogError::UpdateKvpFailed(e.to_string()).into());
                    return Some(Err(self.error.clone().unwrap()));
                }
            }
            // update the lock script to validate the next entry
            self.lock_scripts.clone_from(&entry.locks);
            // update the seqno
            self.prev_seqno = self.seqno;
            self.seqno += 1;
        } else {
            // set our index out of range
            self.seqno = self.entries.len();
            self.error = Some(
                LogError::VerifyFailed(format!(
                    "unlock script failed\nvalues:\n{:?}\nreturn:\n{:?}",
                    rstack, pstack
                ))
                .into(),
            );
            return Some(Err(self.error.clone().unwrap()));
        }

        // return the check count, validated entry, and kvp state
        Some(Ok((count, entry.clone(), self.kvp.clone())))
    }
}

impl Log {
    /// get an iterator over the entries in from head to foot
    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        // get a list of Entry references, sort them by seqno
        let mut entries: Vec<&Entry> = self.entries.values().collect();
        entries.sort();
        EntryIter {
            entries,
            current: 0,
        }
    }

    /// Verifies all entries in the log
    pub fn verify(&self) -> impl Iterator<Item = Result<(usize, Entry, Kvp<'_>), Error>> {
        // get a list of Entry objects, sort them by seqno
        let mut entries: Vec<&Entry> = self.entries.values().collect();
        entries.sort();
        VerifyIter {
            entries,
            seqno: 0,
            prev_seqno: 0,
            kvp: Kvp::default(),
            lock_scripts: vec![self.first_lock.clone()],
            error: None,
        }
    }

    /// Try to add an entry to the p.log
    pub fn try_append(&mut self, entry: &Entry) -> Result<(), Error> {
        let cid = entry.cid();
        let mut plog = self.clone();
        plog.entries.insert(cid.clone(), entry.clone());
        let vi = plog.verify();
        for ret in vi {
            if let Some(e) = ret.err() {
                return Err(LogError::VerifyFailed(e.to_string()).into());
            }
        }
        self.entries.insert(cid.clone(), entry.clone());
        self.head = cid;
        Ok(())
    }
}

/// Builder for Log objects
#[derive(Clone, Default)]
#[allow(dead_code)]
pub struct Builder {
    version: u64,
    vlad: Option<Vlad>,
    first_lock: Option<Script>,
    foot: Option<Cid>,
    head: Option<Cid>,
    entries: Entries,
}

impl Builder {
    /// build new with version
    pub fn new() -> Self {
        Self {
            version: LOG_VERSION,
            ..Default::default()
        }
    }

    /// Set the Vlad
    pub fn with_vlad(mut self, vlad: &Vlad) -> Self {
        self.vlad = Some(vlad.clone());
        self
    }

    /// Set the lock script for the first Entry
    pub fn with_first_lock(mut self, script: &Script) -> Self {
        self.first_lock = Some(script.clone());
        self
    }

    /// Set the foot Cid
    pub fn with_foot(mut self, cid: &Cid) -> Self {
        self.foot = Some(cid.clone());
        self
    }

    /// Set the head Cid
    pub fn with_head(mut self, cid: &Cid) -> Self {
        self.head = Some(cid.clone());
        self
    }

    /// Set the passed in entries to the existin entries
    pub fn with_entries(mut self, entries: &Entries) -> Self {
        self.entries.append(&mut entries.clone());
        self
    }

    /// Add an entry at the head of the log and adjust the head and possibly
    /// the foot if this is the only entry
    pub fn append_entry(mut self, entry: &Entry) -> Self {
        let cid = entry.cid();
        self.head = Some(cid.clone());
        // update the foot if this is the first entry
        if self.entries.is_empty() {
            self.foot = Some(cid.clone());
        }
        self.entries.insert(cid.clone(), entry.clone());
        self
    }

    /// Try to build the Log
    pub fn try_build(&self) -> Result<Log, Error> {
        let version = self.version;
        let vlad = self.vlad.clone().ok_or(LogError::MissingVlad)?;
        let first_lock = self
            .first_lock
            .clone()
            .ok_or(LogError::MissingFirstEntryLockScript)?;
        let foot = self.foot.clone().ok_or(LogError::MissingFoot)?;
        let head = self.head.clone().ok_or(LogError::MissingHead)?;
        let entries = self.entries.clone();
        if entries.is_empty() {
            return Err(LogError::MissingEntries.into());
        } else {
            // start at the head and walk the prev links to the foot to ensure
            // they are all connected
            let mut c = head.clone();
            let f = foot.clone();
            while c != f {
                if let Some(entry) = entries.get(&c) {
                    if c != entry.cid() {
                        return Err(LogError::EntryCidMismatch.into());
                    }
                    c = entry.prev();
                    if c.is_null() {
                        return Err(LogError::BrokenEntryLinks.into());
                    }
                } else {
                    return Err(LogError::BrokenPrevLink.into());
                }
            }
        }
        Ok(Log {
            version,
            vlad,
            first_lock,
            foot,
            head,
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Key, Op, Value};
    use multicid::{cid, vlad};
    use multihash::mh;
    use multikey::{EncodedMultikey, Multikey, Views};
    use std::path::PathBuf;

    fn load_script(path: &Key, file_name: &str) -> Script {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("examples");
        pb.push("wast");
        pb.push(file_name);
        crate::script::Builder::from_code_file(&pb)
            .with_path(path)
            .try_build()
            .unwrap()
    }

    fn get_key_update_op(k: &str, key: &Multikey) -> Op {
        let kcv = key.conv_view().unwrap();
        let pk = kcv.to_public_key().unwrap();
        Op::Update(k.try_into().unwrap(), Value::Data(pk.into()))
    }

    fn get_hash_update_op(k: &str, preimage: &str) -> Op {
        let mh = mh::Builder::new_from_bytes(Codec::Sha3512, preimage.as_bytes())
            .unwrap()
            .try_build()
            .unwrap();
        Op::Update(k.try_into().unwrap(), Value::Data(mh.into()))
    }

    #[test]
    fn test_default() {
        let log = Log::default();
        assert_eq!(Vlad::default(), log.vlad);
        assert_eq!(log.iter().next(), None);
    }

    #[test]
    fn test_builder() {
        let ephemeral = EncodedMultikey::try_from(
            "fba2480260874657374206b6579010120cbd87095dc5863fcec46a66a1d4040a73cb329f92615e165096bd50541ee71c0"
        )
        .unwrap();
        let key = EncodedMultikey::try_from(
            "fba2480260874657374206b6579010120d784f92e18bdba433b8b0f6cbf140bc9629ff607a59997357b40d22c3883a3b8"
        )
        .unwrap();

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

        // build a vlad from the cid
        let vlad = vlad::Builder::default()
            .with_signing_key(&ephemeral)
            .with_cid(&cid)
            .try_build()
            .unwrap();

        // load the entry scripts
        let lock = load_script(&Key::default(), "lock.wast");
        let unlock = load_script(&Key::default(), "unlock.wast");
        let ephemeral_op = get_key_update_op("/ephemeral", &ephemeral);
        let pubkey_op = get_key_update_op("/pubkey", &key);

        let entry = entry::Builder::default()
            .with_vlad(&vlad)
            .add_lock(&lock)
            .with_unlock(&unlock)
            .add_op(&ephemeral_op)
            .add_op(&pubkey_op)
            .try_build(|e| {
                // get the serialized version of the entry (with empty proof)
                let ev: Vec<u8> = e.clone().into();
                // get the signing view on the multikey
                let sv = ephemeral.sign_view().unwrap();
                // generate the signature over the event
                let ms = sv.sign(&ev, false, None).unwrap();
                // store the signature as proof
                Ok(ms.into())
            })
            .unwrap();

        // load the first lock script
        let first = load_script(&Key::default(), "first.wast");

        let log = Builder::new()
            .with_vlad(&vlad)
            .with_first_lock(&first)
            .append_entry(&entry)
            .try_build()
            .unwrap();

        assert_eq!(vlad, log.vlad);
        assert!(!log.foot.is_null());
        assert!(!log.head.is_null());
        assert_eq!(log.foot, log.head);
        assert_eq!(Some(entry), log.iter().next().cloned());
        let mut verify_iter = log.verify();
        while let Some(ret) = verify_iter.next() {
            if let Some(e) = ret.err() {
                println!("verify failed: {}", e.to_string());
            }
        }
    }

    #[test]
    fn test_entry_iterator() {
        let ephemeral = EncodedMultikey::try_from(
            "fba2480260874657374206b6579010120cbd87095dc5863fcec46a66a1d4040a73cb329f92615e165096bd50541ee71c0"
        )
        .unwrap();
        let key1 = EncodedMultikey::try_from(
            "fba2480260874657374206b6579010120d784f92e18bdba433b8b0f6cbf140bc9629ff607a59997357b40d22c3883a3b8"
        )
        .unwrap();
        let key2 = EncodedMultikey::try_from(
            "fba2480260874657374206b65790101203f4c94407de791e53b4df12ef1d5534d1b19ff2ccfccba4ccc4722b6e5e8ea07"
        )
        .unwrap();
        let key3 = EncodedMultikey::try_from(
            "fba2480260874657374206b6579010120518e3ea918b1168d29ca7e75b0ca84be1ad6edf593a47828894a5f1b94a83bd4"
        )
        .unwrap();

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

        // create a vlad
        let vlad = vlad::Builder::default()
            .with_signing_key(&ephemeral)
            .with_cid(&cid)
            .try_build()
            .unwrap();

        let ephemeral_op = get_key_update_op("/ephemeral", &ephemeral);
        let pubkey1_op = get_key_update_op("/pubkey", &key1);
        let pubkey2_op = get_key_update_op("/pubkey", &key2);
        let pubkey3_op = get_key_update_op("/pubkey", &key3);
        let preimage1_op = get_hash_update_op("/hash", "for great justice");
        let preimage2_op = get_hash_update_op("/hash", "move every zig");

        // load the entry scripts
        let lock = load_script(&Key::default(), "lock.wast");
        let unlock = load_script(&Key::default(), "unlock.wast");

        // create the first, self-signed Entry object
        let e1 = entry::Builder::default()
            .with_vlad(&vlad)
            .with_seqno(0)
            .add_lock(&lock) // "/" -> lock.wast
            .with_unlock(&unlock)
            .add_op(&ephemeral_op) // "/ephemeral"
            .add_op(&pubkey1_op) // "/pubkey"
            .add_op(&preimage1_op) // "/preimage"
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let sv = ephemeral.sign_view().unwrap();
                let ms = sv.sign(&ev, false, None).unwrap();
                Ok(ms.into())
            })
            .unwrap();

        //println!("{:?}", e1);
        let e2 = entry::Builder::default()
            .with_vlad(&vlad)
            .with_seqno(1)
            .add_lock(&lock) // "/" -> lock.wast
            .with_unlock(&unlock)
            .with_prev(&e1.cid())
            .add_op(&Op::Delete("/ephemeral".try_into().unwrap())) // "/ephemeral"
            .add_op(&pubkey2_op) // "/pubkey"
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let sv = key1.sign_view().unwrap();
                let ms = sv.sign(&ev, false, None).unwrap();
                Ok(ms.into())
            })
            .unwrap();

        //println!("{:?}", e2);
        let e3 = entry::Builder::default()
            .with_vlad(&vlad)
            .with_seqno(2)
            .add_lock(&lock) // "/" -> lock.wast
            .with_unlock(&unlock)
            .with_prev(&e2.cid())
            .try_build(|e| {
                let ev: Vec<u8> = e.clone().into();
                let sv = key2.sign_view().unwrap();
                let ms = sv.sign(&ev, false, None).unwrap();
                Ok(ms.into())
            })
            .unwrap();

        //println!("{:?}", e3);
        let e4 = entry::Builder::default()
            .with_vlad(&vlad)
            .with_seqno(3)
            .add_lock(&lock) // "/" -> lock.wast
            .with_unlock(&unlock)
            .with_prev(&e3.cid())
            .add_op(&pubkey3_op) // "/pubkey"
            .add_op(&preimage2_op) // "/preimage"
            .try_build(|_| Ok(b"for great justice".to_vec()))
            .unwrap();
        //println!("{:?}", e4);

        // load the first lock script
        let first = load_script(&Key::default(), "first.wast");

        let log = Builder::new()
            .with_vlad(&vlad)
            .with_first_lock(&first)
            .append_entry(&e1) // foot
            .append_entry(&e2)
            .append_entry(&e3)
            .append_entry(&e4) // head
            .try_build()
            .unwrap();

        assert_eq!(vlad, log.vlad);
        assert_eq!(4, log.entries.len());
        let mut iter = log.iter();
        assert_eq!(Some(&e1), iter.next());
        assert_eq!(Some(&e2), iter.next());
        assert_eq!(Some(&e3), iter.next());
        assert_eq!(Some(&e4), iter.next());
        assert_eq!(None, iter.next());
        let mut verify_iter = log.verify();
        while let Some(ret) = verify_iter.next() {
            match ret {
                Ok((c, _, _)) => {
                    println!("check count: {}", c);
                }
                Err(e) => {
                    println!("verify failed: {}", e.to_string());
                    panic!();
                }
            }
        }
    }
}

/*
the gifts of wilderness are given
—in no small measure or part—
to those who call it livin'
having outside inside their heart
*/
