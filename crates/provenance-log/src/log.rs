// SPDX-License-Identifier: FSL-1.1
use crate::{
    entry,
    error::{LogError, ScriptError},
    Entry, Error, Kvp, Script,
};
use comrade::{Comrade, Value};
use core::fmt;
use multibase::Base;
use multicid::{Cid, Vlad};
use multicodec::Codec;
use multitrait::{Null, TryDecodeFrom};
use multiutil::{BaseEncoded, CodecInfo, EncodingInfo, Varuint};
use std::collections::BTreeMap;

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
    prev_cid: Cid,
    kvp: Kvp<'a>,
    lock_scripts: Vec<Script>,
}

impl<'a> Iterator for VerifyIter<'a> {
    type Item = Result<(usize, Entry, Kvp<'a>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        // Check if we've reached the end of entries
        let entry = self.entries.get(self.seqno)?;
        let entry = *entry;

        // this is the check count if successful
        let mut count = 0;

        // check the seqno meet the criteria
        if self.seqno > 0 && self.seqno != self.prev_seqno + 1 {
            self.seqno = self.entries.len(); // End the iterator
            return Some(Err(LogError::InvalidSeqno.into()));
        }

        // check if the cid meets the criteria
        if self.seqno > 0 && entry.prev() != self.prev_cid {
            self.seqno = self.entries.len(); // End the iterator
            return Some(Err(LogError::EntryCidMismatch.into()));
        }

        // 'unlock:
        let Script::Code(_, ref unlock) = entry.unlock else {
            self.seqno = self.entries.len(); // End the iterator
            return Some(Err(Error::Script(ScriptError::WrongScriptFormat {
                expected: "unlock".to_string(),
                found: format!("{:?}", entry.unlock),
            })));
        };

        // if this is the first entry, then we need to apply the
        // mutation ops
        if self.seqno == 0 {
            if let Err(e) = self.kvp.apply_entry_ops(entry) {
                self.seqno = self.entries.len(); // End the iterator
                return Some(Err(LogError::UnlockFailed(e.to_string()).into()));
            }
        }

        let kvp_lock = self.kvp.clone();

        tracing::debug!(
            "verifying entry with seqno {} and prev_seqno {} unlock script: {:?}",
            self.seqno,
            self.prev_seqno,
            unlock
        );

        let mut unlocked = match Comrade::new(&kvp_lock, &entry).try_unlock(unlock) {
            Ok(u) => u,
            Err(e) => {
                tracing::error!("unlock failed: {}", e);
                self.seqno = self.entries.len(); // End the iterator
                return Some(Err(
                    LogError::UnlockFailed(format!("unlock failed: {}", e)).into()
                ));
            }
        };

        // show lock scripts
        tracing::debug!(
            "entry seqno {} has {:?} lock scripts",
            self.seqno,
            self.lock_scripts
        );

        // build the set of lock scripts to run in order from root to longest branch to leaf
        let locks = match entry.sort_locks(&self.lock_scripts) {
            Ok(l) => l,
            Err(e) => {
                self.seqno = self.entries.len(); // End the iterator
                return Some(Err(e));
            }
        };

        let mut results = false;

        // run each of the lock scripts
        for lock in locks {
            let Script::Code(_, lock) = lock else {
                self.seqno = self.entries.len(); // End the iterator
                return Some(Err(ScriptError::WrongScriptFormat {
                    found: format!("{:?}", lock),
                    expected: "Script::Code".to_string(),
                }
                .into()));
            };

            match unlocked.try_lock(&lock) {
                Ok(Some(Value::Success(ct))) => {
                    count = ct;
                    results = true;
                    break;
                }
                Err(e) => {
                    self.seqno = self.entries.len(); // End the iterator
                    return Some(Err(LogError::LockFailed(e.to_string()).into()));
                }
                _ => continue,
            }
        }

        if !results {
            self.seqno = self.entries.len(); // End the iterator
            return Some(Err(LogError::VerifyFailed(
                "entry failed to verify".to_string(),
            )
            .into()));
        }

        // if the entry verifies, apply it's mutatations to the kvp
        // the 0th entry has already been applied at this point so no
        // need to do it here
        if self.seqno > 0 {
            if let Err(e) = self.kvp.apply_entry_ops(entry) {
                self.seqno = self.entries.len(); // End the iterator
                return Some(Err(LogError::UpdateKvpFailed(e.to_string()).into()));
            }
        }

        // update the lock script to validate the next entry
        self.lock_scripts.clone_from(&entry.locks);
        // update the seqno and prev_cid
        self.prev_seqno = self.seqno;
        self.prev_cid = entry.cid();
        self.seqno += 1;

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
            prev_cid: Cid::null(),
            kvp: Kvp::default(),
            lock_scripts: vec![self.first_lock.clone()],
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
    use test_log::test;
    use tracing::{span, Level};
    use tracing_subscriber::{fmt, EnvFilter};

    fn first_lock_script() -> Script {
        Script::Code(
            Key::default(),
            r#"
                check_signature("/ephemeral", "/entry/")
            "#
            .to_string(),
        )
    }

    fn lock_script() -> Script {
        Script::Code(
            Key::default(),
            r#"
                check_signature("/recovery", "/entry/") ||
                check_signature("/pubkey", "/entry/") ||
                check_preimage("/hash")
            "#
            .to_string(),
        )
    }

    fn unlock_script() -> Script {
        Script::Code(
            Key::default(),
            r#"
push("/entry/");
push("/entry/proof");
"#
            .to_string(),
        )
    }

    #[allow(unused)]
    fn init_logger() {
        let subscriber = fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .finish();
        if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
            tracing::warn!("failed to set subscriber: {}", e);
        }
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
        let _s = span!(Level::INFO, "test_default").entered();
        let log = Log::default();
        assert_eq!(Vlad::default(), log.vlad);
        assert_eq!(log.iter().next(), None);
    }

    #[test]
    fn test_builder() {
        let _s = span!(Level::INFO, "test_builder").entered();
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
            .try_build(|cid, _| {
                // sign those bytes
                let v: Vec<u8> = cid.clone().into();
                Ok(v)
            })
            .unwrap();

        // load the entry scripts
        let lock = lock_script();
        let unlock = unlock_script();
        let ephemeral_op = get_key_update_op("/ephemeral", &ephemeral);
        let pubkey_op = get_key_update_op("/pubkey", &key);

        let entry = Entry::builder()
            .vlad(vlad.clone())
            .locks(vec![lock])
            .unlock(unlock)
            .ops(vec![ephemeral_op, pubkey_op])
            .build();

        entry
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
        let first = first_lock_script();

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
        let verify_iter = log.verify();
        for ret in verify_iter {
            if let Some(e) = ret.err() {
                println!("verify failed: {}", e);
            }
        }
    }

    #[test]
    fn test_entry_iterator() {
        let _s = span!(Level::INFO, "test_entry_iterator").entered();
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
            .try_build(|cid, _| {
                // sign those bytes
                let v: Vec<u8> = cid.clone().into();
                Ok(v)
            })
            .unwrap();

        let ephemeral_op = get_key_update_op("/ephemeral", &ephemeral);
        let pubkey1_op = get_key_update_op("/pubkey", &key1);
        let pubkey2_op = get_key_update_op("/pubkey", &key2);
        let pubkey3_op = get_key_update_op("/pubkey", &key3);
        let preimage1_op = get_hash_update_op("/hash", "for great justice");
        let preimage2_op = get_hash_update_op("/hash", "move every zig");

        // load the entry scripts
        let unlock = unlock_script();
        let lock = lock_script();

        // create the first, self-signed Entry object
        let e1 = Entry::builder()
            .vlad(vlad.clone())
            .seqno(0)
            .locks(vec![lock.clone()])
            .unlock(unlock.clone())
            .ops(vec![
                ephemeral_op.clone(),
                pubkey1_op.clone(),
                preimage1_op.clone(),
            ])
            .build();

        let unsigned_entry = e1.prepare_unsigned_entry().unwrap();
        let entry_bytes: Vec<u8> = unsigned_entry.clone().into();

        let signature = {
            let sv = ephemeral.sign_view().unwrap();
            sv.sign(&entry_bytes, false, None).unwrap()
        };

        let e1 = unsigned_entry
            .try_build_with_proof(signature.into())
            .expect("should build e1 with proof");

        let e2 = Entry::builder()
            .vlad(vlad.clone())
            .seqno(1)
            .locks(vec![lock.clone()])
            .unlock(unlock.clone())
            .prev(e1.cid())
            .ops(vec![
                Op::Delete("/ephemeral".try_into().unwrap()),
                pubkey2_op.clone(), // Changed from preimage1_op to pubkey2_op
            ])
            .build();

        let unsigned_entry = e2.prepare_unsigned_entry().unwrap();
        let entry_bytes: Vec<u8> = unsigned_entry.clone().into();

        let signature = {
            let sv = key1.sign_view().unwrap();
            sv.sign(&entry_bytes, false, None).unwrap()
        };

        let e2 = unsigned_entry
            .try_build_with_proof(signature.into())
            .expect("should build e2 with proof");

        let e3 = Entry::builder()
            .vlad(vlad.clone())
            .seqno(2)
            .locks(vec![lock.clone()])
            .unlock(unlock.clone())
            .prev(e2.cid())
            .build();

        let unsigned_entry = e3.prepare_unsigned_entry().unwrap();
        let entry_bytes: Vec<u8> = unsigned_entry.clone().into();

        let signature = {
            let sv = key2.sign_view().unwrap();
            sv.sign(&entry_bytes, false, None).unwrap()
        };

        let e3 = unsigned_entry
            .try_build_with_proof(signature.into())
            .expect("should build e3 with proof");

        let e4 = Entry::builder()
            .vlad(vlad.clone())
            .seqno(3)
            .locks(vec![lock])
            .unlock(unlock)
            .prev(e3.cid())
            .ops(vec![pubkey3_op, preimage2_op])
            .build();

        let unsigned_entry = e4.prepare_unsigned_entry().unwrap();

        // For e4, use the raw bytes "for great justice" as the proof,
        // just like in the original test
        let e4 = unsigned_entry
            .try_build_with_proof(b"for great justice".to_vec())
            .expect("should build e4 with proof");

        // load the first lock script
        let first = first_lock_script();

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

        // Add some debug info to help trace any issues
        println!("Verifying entries...");

        let verify_iter = log.verify();
        for ret in verify_iter {
            match ret {
                Ok((c, e, _)) => {
                    println!("check count for entry with seqno {}: {}", e.seqno(), c);
                }
                Err(e) => {
                    println!("verify failed: {}", e);
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
