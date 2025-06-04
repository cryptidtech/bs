//! When a consumer gets a verifiable long-lived address (VLAD), it maps
//! to the Plog Head Content Identifier (CID) that maps to the actual data stored
//! somewhere in content addressed storage.
//!
//! The Data Provenance Log (plog) needs to thus resolve the CID to the
//! actual plog entries at which the CIDs point.
//!
//! This process is called resolving, and since the content addressed storage
//! could be many types, the resolution process is defined by the user.
//!
//! Users can implement the [Resolver] trait to define how to resolve the data
//! from a CID chain.
use crate::{log, Entry, Error as PlogError, Log, Op, Script, Value};

use multicid::Cid;
use multitrait::Null;
use multiutil::CodecInfo;
use std::{collections::BTreeMap, future::Future, pin::Pin};

/// Result of resolving entries in a plog chain
#[derive(Debug, Clone)]
pub struct EntriesFootprint {
    /// The entries in the chain, from head to foot
    pub entries: BTreeMap<Cid, Entry>,

    /// The CID of the foot entry (the last entry in the chain)
    pub foot_cid: Cid,
}

impl EntriesFootprint {
    /// Get the last entry in the chain (the foot)
    pub fn foot(&self) -> Option<&Entry> {
        self.entries.get(&self.foot_cid)
    }
}

/// Result of resolving and verifying a Plog
#[derive(Debug, Clone)]
pub struct ResolvedPlog {
    /// The reconstructed and verified provenance log
    pub log: Log,

    /// The verification counts for each step in the verification process
    /// Stored in order from latest to earliest entry
    pub verification_counts: Vec<usize>,
}

impl ResolvedPlog {
    /// Compare this resolved plog with another and determine which has the lower verification cost
    ///
    /// Returns:
    /// - Ordering::Less if this plog has a lower verification cost
    /// - Ordering::Greater if the other plog has a lower verification cost
    /// - Ordering::Equal if they have the same verification cost
    ///
    /// The comparison is done by examining each verification step, starting from the most recent entry.
    /// At the first differing count, the plog with the lower count is considered "less".
    pub fn compare(&self, other: &ResolvedPlog) -> std::cmp::Ordering {
        // Compare counts from the most recent (latest) entries first
        for (self_count, other_count) in self
            .verification_counts
            .iter()
            .zip(other.verification_counts.iter())
        {
            match self_count.cmp(other_count) {
                std::cmp::Ordering::Equal => continue, // If equal, check the next count
                order => return order, // Return the ordering at the first difference
            }
        }

        // If we've compared all common entries and they're equal, compare by length
        // Longer chains are kept as this is how they are updated
        // Keep longer is same.
        other
            .verification_counts
            .len()
            .cmp(&self.verification_counts.len())
    }

    /// Calculate the total verification count across all steps
    pub fn total_count(&self) -> usize {
        self.verification_counts.iter().sum()
    }

    /// Returns true if this plog has a lower verification cost than the other
    pub fn is_cheaper_than(&self, other: &ResolvedPlog) -> bool {
        self.compare(other) == std::cmp::Ordering::Less
    }
}

/// A trait for resolving data from a Cid and working with plog entries.
///
/// # Example
///
/// ```rust
/// use std::pin::Pin;
/// use std::future::Future;
/// use std::sync::Arc;
/// use tokio::sync::Mutex;
/// use multicid::Cid;
/// use provenance_log::Entry;
/// use provenance_log::resolver::Resolver;
///
/// struct MyResolver {
///    // Your resolver state, e.g. a database connection or HTTP client
/// }
///
/// #[derive(thiserror::Error, Debug)]
/// enum MyError {
///    #[error("MultiCid error: {0}")]
///    MultiCidError(#[from] multicid::Error),
///    #[error("MultiHash error: {0}")]
///    MultiHashError(#[from] multihash::Error),
///    #[error("Provenance Log error: {0}")]
///    PlogError(#[from] provenance_log::Error),
///    #[error("Resolve error: {0}")]
///    ResolveError(#[from] provenance_log::resolver::ResolveError),
/// }
///
/// impl Resolver for MyResolver {
///    type Error = MyError;
///
///    fn resolve(
///        &self,
///        cid: &Cid,
///    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::Error>> + Send>> {
///        Box::pin(async move {
///           todo!(); // get your data from the state struct, e.g. a database or HTTP request
///        })
///    }
/// }
/// ```
#[allow(clippy::type_complexity)]
pub trait Resolver {
    /// The error type returned by resolver operations
    type Error: std::error::Error
        + From<multicid::Error>
        + From<multihash::Error>
        + From<PlogError>
        + From<ResolveError>
        + 'static;

    /// Core method to resolve a CID into bytes
    fn resolve(
        &self,
        cid: &Cid,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::Error>> + Send>>;

    /// Helper method to verify that a CID matches the content
    fn verify_cid_match(&self, cid: &Cid, data: &[u8]) -> Result<(), Self::Error> {
        let rebuilt_cid = multicid::cid::Builder::new(multicodec::Codec::Cidv1)
            .with_target_codec(cid.target_codec)
            .with_hash(&multihash::Builder::new_from_bytes(cid.hash.codec(), data)?.try_build()?)
            .try_build()?;

        if rebuilt_cid != *cid {
            return Err(ResolveError::VerifyCidError {
                expected: cid.clone(),
                got: rebuilt_cid,
            }
            .into());
        }

        Ok(())
    }

    /// Recursively get the resolved data from a head [Cid] down to the foot [Cid],
    /// returning the entries and foot CID.
    ///
    /// Returns an [EntriesFootprint] containing [BTreeMap] of both [Entry]s and the foot [Cid].
    fn get_entry_chain(
        &self,
        head_cid: &Cid,
    ) -> impl Future<Output = Result<EntriesFootprint, Self::Error>> + Send
    where
        Self: Sync,
    {
        async {
            let mut entries = BTreeMap::new();
            let mut current_cid = head_cid.clone();
            let foot_cid;

            loop {
                let entry_bytes = self.resolve(&current_cid).await?;

                // Verify the CID matches the entry bytes
                self.verify_cid_match(&current_cid, &entry_bytes)?;

                // Parse the entry
                let entry = Entry::try_from(entry_bytes.as_slice())?;

                // Store the entry
                entries.insert(current_cid.clone(), entry.clone());

                if entry.prev() == Null::null() {
                    foot_cid = current_cid; // Save the foot CID
                    break;
                }
                current_cid = entry.prev();
            }

            Ok(EntriesFootprint { entries, foot_cid })
        }
    }

    /// Given the head Cid, resolve the Plog entries,
    /// rebuild the Plog, and verify it.
    fn resolve_plog(
        &self,
        head_cid: &Cid,
    ) -> impl Future<Output = Result<ResolvedPlog, Self::Error>> + Send
    where
        Self: Sync,
    {
        async {
            let entry_chain = self.get_entry_chain(head_cid).await?;

            tracing::info!(
                "Retrieved entry chain with {} entries",
                entry_chain.entries.len()
            );

            let entry = if entry_chain.entries.len() == 1 {
                // For a single entry chain, head and foot are the same, so we can use
                // the head bytes we already fetched when building the entry_chain
                tracing::debug!("Single entry chain - head and foot are the same");
                entry_chain.foot().cloned().unwrap()
            } else {
                // For multiple entries, resolve the foot separately
                tracing::debug!("Multiple entries - resolving foot CID");
                let entry_bytes = self.resolve(&entry_chain.foot_cid).await?;

                tracing::debug!("Foot resolved. Converting to Entry...");
                Entry::try_from(entry_bytes.as_slice())?
            };

            let vlad = entry.vlad();

            let first_lock_cid = vlad.cid();

            tracing::info!("First lock CID: {}", first_lock_cid);

            // We store the first lock bytes under /vlad/data key in the Entry kvp
            // TODO: Type the vlad.data key properly
            let Value::Data(first_lock_bytes) = entry
                // TODO: Should be able to do this:
                // entry.get_value(&Key::try_from("/vlad/data")?)
                // .ok_or(ResolveError::ResolveCidError(format!(
                //     "First lock CID not found in entry: {}",
                //     first_lock_cid
                // )))?
                .ops()
                .find_map(|op| {
                    if let Op::Update(key, value) = op {
                        if key.as_str() == "/vlad/data" {
                            return Some(value);
                        }
                    }
                    None
                })
                .ok_or(ResolveError::ResolveCidError(format!(
                    "First lock CID not found in entry: {}",
                    first_lock_cid
                )))?
            else {
                return Err(ResolveError::ParseEntryError(format!(
                    "First lock CID value is not of type Data in entry: {}",
                    first_lock_cid
                ))
                .into());
            };

            tracing::debug!("First lock bytes: {:?}", first_lock_bytes);

            let first_lock_script = Script::try_from(first_lock_bytes.as_slice())?;

            tracing::debug!("First lock script built Rebuilt plog");

            let rebuilt_plog = log::Builder::new()
                .with_vlad(&vlad)
                .with_first_lock(&first_lock_script)
                .with_entries(&entry_chain.entries)
                .with_head(head_cid)
                .with_foot(&entry_chain.foot_cid)
                .try_build()?;

            let plog_clone = rebuilt_plog.clone();

            let verify_iter = &mut plog_clone.verify();

            // Check that first entry matches (using debug_assert for development checks)
            if let Some(head_entry) = entry_chain.entries.get(head_cid) {
                debug_assert_eq!(rebuilt_plog.entries[head_cid], head_entry.clone());
            }

            // Collect individual verification counts
            let mut verification_counts = Vec::new();

            // the log should also verify
            for ret in verify_iter {
                match ret {
                    Ok((count, entry, kvp)) => {
                        verification_counts.push(count);
                        tracing::trace!("Verified entry: {:#?}", entry);
                        tracing::trace!("Verified count: {:#?}", count);
                        tracing::trace!("Verified kvp: {:#?}", kvp);
                    }
                    Err(e) => {
                        tracing::error!("Error: {:#?}", e);
                        return Err(PlogError::Log(crate::error::LogError::VerifyFailed(
                            e.to_string(),
                        ))
                        .into());
                    }
                }
            }

            Ok(ResolvedPlog {
                log: rebuilt_plog,
                verification_counts,
            })
        }
    }
}

/// Errors that can occur during the resolution process
#[derive(thiserror::Error, Clone, Debug)]
pub enum ResolveError {
    /// Error resolving the CID
    #[error("Error resolving CID: {0}")]
    ResolveCidError(String),

    /// Error verifying the CID matches the content
    #[error("CID verification failed: expected {expected}, got {got}")]
    VerifyCidError {
        /// Expected: Cid
        expected: Cid,
        /// Actual Cid
        got: Cid,
    },

    /// Error parsing the entry
    #[error("Error parsing entry: {0}")]
    ParseEntryError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn test_resolved_plog_comparison() {
        // Create plogs with different verification counts
        let log1 = Log::default();
        let log2 = Log::default();

        // Case 1: First plog is cheaper in the first entry
        let plog1 = ResolvedPlog {
            log: log1.clone(),
            verification_counts: vec![1, 2, 3],
        };

        let plog2 = ResolvedPlog {
            log: log2.clone(),
            verification_counts: vec![2, 2, 3],
        };

        assert_eq!(plog1.compare(&plog2), Ordering::Less);
        assert!(plog1.is_cheaper_than(&plog2));

        // Case 2: Same count in first entry, second plog cheaper in second entry
        let plog3 = ResolvedPlog {
            log: log1.clone(),
            verification_counts: vec![1, 3, 3],
        };

        let plog4 = ResolvedPlog {
            log: log2.clone(),
            verification_counts: vec![1, 2, 3],
        };

        assert_eq!(plog3.compare(&plog4), Ordering::Greater);
        assert!(plog4.is_cheaper_than(&plog3));

        // Case 3: Equal counts but different lengths (longer one is kept)
        let plog5 = ResolvedPlog {
            log: log1.clone(),
            verification_counts: vec![1, 2],
        };

        let plog6 = ResolvedPlog {
            log: log2.clone(),
            verification_counts: vec![1, 2, 3],
        };

        assert_eq!(plog5.compare(&plog6), Ordering::Greater); // plog6 is kept (longer)
        assert!(!plog5.is_cheaper_than(&plog6));

        // Test total_count
        assert_eq!(plog1.total_count(), 6);
        assert_eq!(plog6.total_count(), 6);
    }
}
