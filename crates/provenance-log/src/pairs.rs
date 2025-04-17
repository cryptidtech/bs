// SPDX-License-Identifier: FSL-1.1
use crate::{error::KvpError, Entry, Error, Key, Op, Value};
use std::{collections::BTreeMap, fmt};

/// Kvp is the virtual key-value pair storage system that builds up the state
/// encoded in provenance logs as time series of verifiable state changes.
#[derive(Clone, Debug, Default)]
pub struct Kvp<'a> {
    /// the key-value pair store itself
    kvp: BTreeMap<Key, Value>,
    /// the entry so we can expose it as part of the key-vale store
    entry: Option<&'a Entry>,
    /// this stores state snapshots from just before applying an entry.
    undo: Vec<(Option<&'a Entry>, BTreeMap<Key, Value>)>,
}

impl wacc::Pairs for Kvp<'_> {
    fn get(&self, key: &str) -> Option<wacc::Value> {
        let k = match Key::try_from(key) {
            Ok(k) => k,
            _ => return None,
        };
        match self.kvp.get(&k) {
            Some(ref v) => match v {
                Value::Nil => Some(wacc::Value::Bin {
                    hint: key.to_string(),
                    data: Vec::default(),
                }),
                Value::Str(ref s) => Some(wacc::Value::Str {
                    hint: key.to_string(),
                    data: s.clone(),
                }),
                Value::Data(ref v) => Some(wacc::Value::Bin {
                    hint: key.to_string(),
                    data: v.clone(),
                }),
            },
            None => {
                if let Some(entry) = self.entry {
                    entry.get(key)
                } else {
                    None
                }
            }
        }
    }

    fn put(&mut self, key: &str, value: &wacc::Value) -> Option<wacc::Value> {
        let k = match Key::try_from(key) {
            Ok(k) => k,
            _ => return None,
        };
        let v = match value {
            wacc::Value::Str {
                hint: _,
                data: ref s,
            } => Value::Str(s.clone()),
            wacc::Value::Bin {
                hint: _,
                data: ref v,
            } => Value::Data(v.clone()),
            _ => return None,
        };
        match self.kvp.insert(k, v) {
            Some(Value::Nil) => Some(wacc::Value::Bin {
                hint: key.to_string(),
                data: Vec::default(),
            }),
            Some(Value::Str(s)) => Some(wacc::Value::Str {
                hint: key.to_string(),
                data: s,
            }),
            Some(Value::Data(v)) => Some(wacc::Value::Bin {
                hint: key.to_string(),
                data: v,
            }),
            None => None,
        }
    }
}

impl fmt::Display for Kvp<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (k, v) in self.kvp.iter() {
            match v {
                Value::Nil => writeln!(f, "'{}' -> nil", k)?,
                Value::Str(s) => writeln!(f, "'{}' -> {}", k, s)?,
                Value::Data(v) => writeln!(f, "'{}' -> data of length: {}", k, v.len())?,
            }
        }
        write!(f, "")
    }
}

impl<'a> Kvp<'a> {
    /// get an iterator over the keys and values
    pub fn iter(&self) -> impl Iterator<Item = (&Key, &Value)> {
        self.kvp.iter()
    }

    /// sets the entry to look for values in as well
    pub fn set_entry(&mut self, entry: &'a Entry) -> Result<Option<u64>, Error> {
        match self.entry {
            // if this is the first entry processed, make sure the entry's seqno is 0
            None => {
                if entry.seqno() != 0 {
                    return Err(KvpError::NonZeroSeqNo.into());
                }
            }
            // if the seqno is > 0, make sure the entry's seqno is seqno + 1
            Some(e) => {
                if entry.seqno() != e.seqno + 1 {
                    return Err(KvpError::InvalidSeqNo.into());
                }
            }
        }

        // take a snapshot for the undo stack
        self.snapshot();

        // update the entry
        self.entry = Some(entry);
        Ok(self.seqno())
    }

    /// function for processing the operatios in a given entry and updating the
    /// state of the key-value pair store.
    pub fn apply_entry_ops(&mut self, entry: &'a Entry) -> Result<(), Error> {
        // insert the op mutations and record an undo snapshot with the current
        // seqno so when this is undone, we're back in the proper state
        self.insert_op_mutations(entry)?;
        Ok(())
    }

    /// get the seqno of the current entry if there is one
    pub fn seqno(&self) -> Option<u64> {
        self.entry.map(|entry| entry.seqno)
    }

    /// function to undo the last apply_entry
    pub fn undo_entry(&mut self) -> Result<Option<u64>, Error> {
        // revert the kvp state to just before this entry was added
        if let Some((entry, kvp)) = self.undo.pop() {
            self.kvp = kvp;
            self.entry = entry;
            Ok(self.seqno())
        } else {
            Err(KvpError::EmptyUndoStack.into())
        }
    }

    /// function to take a state snapshot and push it onto the undo stack
    pub(crate) fn snapshot(&mut self) {
        self.undo.push((self.entry, self.kvp.clone()));
    }

    /// function to add the op mutations to the kvp
    pub(crate) fn insert_op_mutations(&mut self, entry: &Entry) -> Result<(), Error> {
        // process the mutation operations
        for op in entry.ops() {
            match op {
                Op::Update(k, v) => {
                    self.kvp.insert(k.clone(), v.clone());
                }
                Op::Delete(k) => {
                    self.kvp.remove(k);
                }
                Op::Noop(_) => {}
            }
        }

        Ok(())
    }

    /// returns the number of key-value pairs in the virtual store
    pub fn len(&self) -> usize {
        self.kvp.len()
    }

    /// returns if the kvp is empty
    pub fn is_empty(&self) -> bool {
        self.kvp.is_empty()
    }

    /// returns the number of entries in the undo sctack
    pub fn undo_len(&self) -> usize {
        self.undo.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{entry, Script};
    use multicid::Vlad;
    use test_log::test;
    use tracing::{span, Level};

    #[test]
    fn test_default() {
        let _ = span!(Level::INFO, "test_default").entered();
        let p = Kvp::default();
        assert_eq!(p.seqno(), None);
        assert_eq!(p.len(), 0);
        assert_eq!(p.undo_len(), 0);
    }

    #[test]
    #[should_panic]
    fn test_bad_undo() {
        let mut p = Kvp::default();
        // this should panic because no entries have been applied
        let _ = p.undo_entry().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_same_seqno() {
        let mut p = Kvp::default();

        let e1 = entry::Builder::default()
            .with_vlad(&Vlad::default())
            .add_lock(&Script::default())
            .with_unlock(&Script::default())
            .try_build(|_| Ok(Vec::default()))
            .unwrap();

        let _ = p.set_entry(&e1).unwrap();
        p.apply_entry_ops(&e1).unwrap();

        let e2 = entry::Builder::default()
            .with_vlad(&Vlad::default())
            .add_lock(&Script::default())
            .with_unlock(&Script::default())
            .try_build(|_| Ok(Vec::default()))
            .unwrap();

        // this panics because the seqno of e1 is the same
        let _ = p.set_entry(&e2).unwrap();
        p.apply_entry_ops(&e2).unwrap();
    }

    #[test]
    fn test_one_entry() {
        let _ = span!(Level::INFO, "test_one_entry").entered();
        let entry = entry::Builder::default()
            .with_vlad(&Vlad::default())
            .add_lock(&Script::default())
            .with_unlock(&Script::default())
            .add_op(&Op::Update(
                "/one".try_into().unwrap(),
                Value::Str("foo".to_string()),
            ))
            .add_op(&Op::Noop("/foo".try_into().unwrap()))
            .add_op(&Op::Update(
                "/two".try_into().unwrap(),
                Value::Str("bar".to_string()),
            ))
            .add_op(&Op::Noop("/bar".try_into().unwrap()))
            .add_op(&Op::Update(
                "/three".try_into().unwrap(),
                Value::Str("baz".to_string()),
            ))
            .try_build(|_| Ok(Vec::default()))
            .unwrap();

        let mut p = Kvp::default();

        // apply the entry
        let mut seqno = p.set_entry(&entry).unwrap();
        p.apply_entry_ops(&entry).unwrap();

        assert_eq!(seqno, Some(0));
        assert_eq!(p.len(), 3);
        assert_eq!(p.undo_len(), 1);
        assert_eq!(
            p.kvp.get(&"/one".try_into().unwrap()),
            Some(&Value::Str("foo".to_string()))
        );

        // undo it and revert back to default state
        seqno = p.undo_entry().unwrap();

        assert_eq!(seqno, None);
        assert_eq!(p.len(), 0);
        assert_eq!(p.undo_len(), 0);
        assert_eq!(p.kvp.get(&"/one".try_into().unwrap()), None);
    }

    /*
    #[test]
    fn test_entries() {
        let mut p = Kvp::default();

        let e1 = entry::Builder::default()
            .with_vlad(&Vlad::default())
            .add_lock(&Script::default())
            .with_unlock(&Script::default())
            .add_op(&Op::Update(
                "one".to_string(),
                Value::Str("foo".to_string()),
            ))
            .add_op(&Op::Noop)
            .add_op(&Op::Update(
                "two".to_string(),
                Value::Str("bar".to_string()),
            ))
            .add_op(&Op::Noop)
            .add_op(&Op::Update(
                "three".to_string(),
                Value::Str("baz".to_string()),
            ))
            .try_build(|e| {
                e.proof = Vec::default();
                Ok(())
            })
            .unwrap();

        let mut seqno = p.set_entry(&e1).unwrap();
        p.apply_entry_ops(&e1).unwrap();
        /*
            seqno: 0,
            kvp: {
                // entry op mutations
                "one": "foo",
                "two": "bar",
                "three": "baz"
            }
        */
        assert_eq!(seqno, Some(0));
        assert_eq!(p.kvp.len(), 3);
        assert_eq!(p.undo.len(), 1);
        assert_eq!(
            p.kvp.get(&"one".to_string()),
            Some(Value::Str("foo".to_string())).as_ref()
        );
        assert_eq!(
            p.kvp.get(&"two".to_string()),
            Some(Value::Str("bar".to_string())).as_ref()
        );
        assert_eq!(
            p.kvp.get(&"three".to_string()),
            Some(Value::Str("baz".to_string())).as_ref()
        );

        let e2 = entry::Builder::default()
            .with_vlad(&Vlad::default())
            .with_seqno(1)
            .add_lock(&Script::default())
            .with_unlock(&Script::default())
            .add_op(&Op::Delete("one".to_string()))
            .add_op(&Op::Update(
                "two".to_string(),
                Value::Str("blah".to_string()),
            ))
            .add_op(&Op::Noop)
            .try_build(|e| {
                e.proof = Vec::default();
                Ok(())
            })
            .unwrap();

        seqno = p.set_entry(&e2).unwrap();
        p.apply_entry_ops(&e2).unwrap();
        /*
            seqno: 1,
            kvp: {
                // entry op mutations
                "two": "blah",
                "three": "baz"
            }
        */
        assert_eq!(seqno, Some(1));
        assert_eq!(p.kvp.len(), 2);
        assert_eq!(p.undo.len(), 2);
        assert_eq!(p.kvp.get(&"one".to_string()), None);
        assert_eq!(
            p.kvp.get(&"two".to_string()),
            Some(Value::Str("blah".to_string())).as_ref()
        );
        assert_eq!(
            p.kvp.get(&"three".to_string()),
            Some(Value::Str("baz".to_string())).as_ref()
        );

        let e3 = entry::Builder::default()
            .with_vlad(&Vlad::default())
            .with_seqno(2)
            .add_lock(&Script::default())
            .with_unlock(&Script::default())
            .add_op(&Op::Update(
                "one".to_string(),
                Value::Str("foo".to_string()),
            ))
            .add_op(&Op::Update(
                "four".to_string(),
                Value::Str("qux".to_string()),
            ))
            .add_op(&Op::Delete("five".to_string()))
            .try_build(|e| {
                e.proof = Vec::default();
                Ok(())
            })
            .unwrap();

        seqno = p.set_entry(&e3).unwrap();
        p.apply_entry_ops(&e3).unwrap();
        /*
            seqno: 2,
            kvp: {
                // entry op mutations
                "one": "foo",
                "two": "blah",
                "three": "baz",
                "four": "qux"
            }
        */

        assert_eq!(seqno, Some(2));
        assert_eq!(p.kvp.len(), 4);
        assert_eq!(p.undo.len(), 3);
        assert_eq!(
            p.kvp.get(&"one".to_string()),
            Some(Value::Str("foo".to_string())).as_ref()
        );
        assert_eq!(
            p.kvp.get(&"two".to_string()),
            Some(Value::Str("blah".to_string())).as_ref()
        );
        assert_eq!(
            p.kvp.get(&"three".to_string()),
            Some(Value::Str("baz".to_string())).as_ref()
        );
        assert_eq!(
            p.kvp.get(&"four".to_string()),
            Some(Value::Str("qux".to_string())).as_ref()
        );
        assert_eq!(p.kvp.get(&"five".to_string()), None);
    }

    #[test]
    fn test_undo_redo() {
        let mut p = Kvp::default();

        let e1 = entry::Builder::default()
            .with_vlad(&Vlad::default())
            .add_lock(&Script::default())
            .with_unlock(&Script::default())
            .add_op(&Op::Update(
                "one".to_string(),
                Value::Str("foo".to_string()),
            ))
            .add_op(&Op::Noop)
            .add_op(&Op::Update(
                "two".to_string(),
                Value::Str("bar".to_string()),
            ))
            .add_op(&Op::Noop)
            .add_op(&Op::Update(
                "three".to_string(),
                Value::Str("baz".to_string()),
            ))
            .try_build(|e| {
                e.proof = Vec::default();
                Ok(())
            })
            .unwrap();

        let mut seqno = p.set_entry(&e1).unwrap();
        p.apply_entry_ops(&e1).unwrap();
        /*
            seqno: 0,
            kvp: {
                // entry op mutations
                "one": "foo",
                "two": "bar",
                "three": "baz"
            }
        */
        assert_eq!(seqno, Some(0));
        assert_eq!(p.kvp.len(), 3);
        // 2 because one snapshot from before the op mutations were applied and
        // one from before the entry attributes were applied
        assert_eq!(p.undo.len(), 1);
        assert_eq!(
            p.kvp.get(&"one".to_string()),
            Some(Value::Str("foo".to_string())).as_ref()
        );
        assert_eq!(
            p.kvp.get(&"two".to_string()),
            Some(Value::Str("bar".to_string())).as_ref()
        );
        assert_eq!(
            p.kvp.get(&"three".to_string()),
            Some(Value::Str("baz".to_string())).as_ref()
        );

        let e2a = entry::Builder::default()
            .with_vlad(&Vlad::default())
            .with_seqno(1)
            .add_lock(&Script::default())
            .with_unlock(&Script::default())
            .add_op(&Op::Delete("one".to_string()))
            .add_op(&Op::Update(
                "two".to_string(),
                Value::Str("blah".to_string()),
            ))
            .add_op(&Op::Noop)
            .try_build(|e| {
                e.proof = Vec::default();
                Ok(())
            })
            .unwrap();

        seqno = p.set_entry(&e2a).unwrap();
        p.apply_entry_ops(&e2a).unwrap();
        /*
            seqno: 1,
            kvp: {
                // entry op mutations
                "two": "blah",
                "three": "baz"
            }
        */
        assert_eq!(seqno, Some(1));
        assert_eq!(p.kvp.len(), 2);
        assert_eq!(p.undo.len(), 2);
        assert_eq!(p.kvp.get(&"one".to_string()), None);
        assert_eq!(
            p.kvp.get(&"two".to_string()),
            Some(Value::Str("blah".to_string())).as_ref()
        );
        assert_eq!(
            p.kvp.get(&"three".to_string()),
            Some(Value::Str("baz".to_string())).as_ref()
        );

        seqno = p.undo_entry().unwrap();
        /*
            seqno: 0,
            kvp: {
                // entry op mutations
                "one": "foo",
                "two": "bar",
                "three": "baz"
            }
        */
        assert_eq!(seqno, Some(0));
        assert_eq!(p.kvp.len(), 3);
        assert_eq!(p.undo.len(), 1);
        assert_eq!(
            p.kvp.get(&"one".to_string()),
            Some(Value::Str("foo".to_string())).as_ref()
        );
        assert_eq!(
            p.kvp.get(&"two".to_string()),
            Some(Value::Str("bar".to_string())).as_ref()
        );
        assert_eq!(
            p.kvp.get(&"three".to_string()),
            Some(Value::Str("baz".to_string())).as_ref()
        );

        let e2b = entry::Builder::default()
            .with_vlad(&Vlad::default())
            .with_seqno(1)
            .add_lock(&Script::default())
            .with_unlock(&Script::default())
            .add_op(&Op::Update(
                "one".to_string(),
                Value::Str("foo".to_string()),
            ))
            .add_op(&Op::Update(
                "four".to_string(),
                Value::Str("qux".to_string()),
            ))
            .add_op(&Op::Delete("five".to_string()))
            .try_build(|e| {
                e.proof = Vec::default();
                Ok(())
            })
            .unwrap();

        seqno = p.set_entry(&e2b).unwrap();
        p.apply_entry_ops(&e2b).unwrap();
        /*
            seqno: 1,
            kvp: {
                // entry op mutations
                "one": "foo",
                "two": "bar",
                "three": "baz",
                "four": "qux"
            }
        */

        assert_eq!(seqno, Some(1));
        assert_eq!(p.kvp.len(), 4);
        assert_eq!(p.undo.len(), 2);
        assert_eq!(
            p.get(&"one"),
            Some(Value::Str("foo".to_string())).as_ref()
        );
        assert_eq!(
            p.get(&"two"),
            Some(Value::Str("bar".to_string())).as_ref()
        );
        assert_eq!(
            p.get(&"three"),
            Some(Value::Str("baz".to_string())).as_ref()
        );
        assert_eq!(
            p.get(&"four"),
            Some(Value::Str("qux".to_string()))
        );
        assert_eq!(p.get(&"five", None));
    }
    */
}
