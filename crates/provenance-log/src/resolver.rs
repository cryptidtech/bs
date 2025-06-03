//! When a consumer gets a verifiable long-lived address (VLAD), it maps
//! to the Plog Head Content Identifier (CID) that maps to the actual data stored
//! somewhere in content addressed storage.
//!
//! The Data Provenance Log (plog) needs the thus resolve the CID to the
//! actual plog entries at which the CIDs point.
//!
//! This process is called resolving, and since the content addressed storage
//! could be many types, the resolution process is defined by the user.
//!
//! Users can implement the [Resolver] trait to define how to resolve the data
//! from a CID chain. Then, the [get_entry_chain] function can be used to get
//! the entries from the head CID down to the foot CID.
use crate::{log, Entry, Log, Script};

use multicid::{Cid, Vlad};
use multitrait::Null;
use multiutil::CodecInfo;
use std::{collections::BTreeMap, future::Future, pin::Pin};

/// Error types for resolution operations
#[derive(thiserror::Error, Debug)]
pub enum ResolveError {
    #[error("Failed to get block from blockstore")]
    BlockNotFound,

    #[error("Log verification failed: {0}")]
    VerificationError(String),

    #[error("CID mismatch: expected {expected}, got {actual}")]
    CidMismatch { expected: Cid, actual: Cid },

    #[error("Failed to get last entry")]
    NoLastEntry,

    #[error("Other error: {0}")]
    Other(#[from] Box<dyn std::error::Error>),
}

/// Helper function to simplify error conversion
fn to_resolve_err<E: std::error::Error + 'static>(err: E) -> ResolveError {
    ResolveError::Other(Box::new(err))
}

/// A trait for resolving data from a Cid.
///
/// # Example
///
/// ```rust
/// use std::pin::Pin;
/// use std::future::Future;
/// use std::sync::Arc;
/// use tokio::sync::Mutex;
/// use bestsign_core::{Entry, Cid};
/// use blockstore::{Blockstore as _, InMemoryBlockstore};
/// use bestsign_core::resolve::Resolver;
///
/// struct Resolve {
///    pub blockstore: Arc<Mutex<InMemoryBlockstore<64>>>,
/// }
///
/// impl Resolver for Resolve {
///    type Error = TestError;
///
///    fn resolve(
///        &self,
///        cid: &Cid,
///    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::Error>> + Send>> {
///        let blockstore = self.blockstore.clone();
///        let cid_bytes: Vec<u8> = (cid.clone()).into();
///        Box::pin(async move {
///            let cid = cid::Cid::try_from(cid_bytes)?;
///            let cid = cid::Cid::try_from(cid_bytes)?;
///
///            let block = blockstore.lock().await.get(&cid).await?
///                .ok_or(TestError::BlockstoreError("Failed to get block from blockstore".into()))?;
///            Ok(block)
///        })
///    }
/// }
///
/// #[derive(thiserror::Error, Debug)]
/// enum TestError {
///    #[error("Blockstore error: {0}")]
///    BlockstoreError(#[from] blockstore::Error),
///    #[error("Cid error: {0}")]
///    CidError(#[from] cid::Error),
/// }
///```
#[allow(clippy::type_complexity)]
pub trait Resolver {
    type Error: std::error::Error + 'static;

    fn resolve(
        &self,
        cid: &Cid,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::Error>> + Send>>;
}

/// Helper function to verify CID matches content
fn verify_cid_match(cid: &Cid, data: &[u8]) -> Result<(), ResolveError> {
    let rebuilt_cid = multicid::cid::Builder::new(multicodec::Codec::Cidv1)
        .with_target_codec(cid.target_codec)
        .with_hash(
            &multihash::Builder::new_from_bytes(cid.hash.codec(), data)
                .map_err(to_resolve_err)?
                .try_build()
                .map_err(to_resolve_err)?,
        )
        .try_build()
        .map_err(to_resolve_err)?;

    if rebuilt_cid != *cid {
        return Err(ResolveError::CidMismatch {
            expected: cid.clone(),
            actual: rebuilt_cid,
        });
    }

    Ok(())
}

/// Result of resolving entries in a plog chain
#[derive(Debug, Clone)]
pub struct EntriesFootprint {
    /// The entries in the chain, from head to foot
    pub entries: BTreeMap<Cid, Entry>,

    /// The CID of the foot entry (the last entry in the chain)
    pub foot_cid: Cid,
}

/// Recursively get the resolved data from a head [Cid] down to the foot [Cid],
/// returning the entries and foot CID.
///
/// Returns an [EntriesFootprint] containing [BTreeMap] of both [Entry]s and the foot [Cid].
pub async fn get_entry_chain(
    head_cid: &Cid,
    get_data: impl Resolver,
) -> Result<EntriesFootprint, ResolveError> {
    let mut entries = BTreeMap::new();
    let mut current_cid = head_cid.clone();
    let foot_cid;

    loop {
        let entry_bytes = get_data
            .resolve(&current_cid)
            .await
            .map_err(to_resolve_err)?;

        // Verify the CID matches the entry bytes
        verify_cid_match(&current_cid, &entry_bytes)?;

        // Parse the entry
        let entry = Entry::try_from(entry_bytes.as_slice()).map_err(to_resolve_err)?;

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

/// Given the vlad and the head Cid, resolve the Plog entries,
/// rebuild the Plog, and verify it.
pub async fn resolve_plog(
    vlad: &Vlad,
    head_cid: &Cid,
    resolver: impl Resolver + Clone,
) -> Result<ResolvedPlog, ResolveError> {
    let entry_chain = get_entry_chain(head_cid, resolver.clone()).await?;

    // Reconstruct the plog from the fetched entries
    let first_lock_cid = vlad.cid();

    let entry_bytes = resolver
        .resolve(first_lock_cid)
        .await
        .map_err(to_resolve_err)?;

    let first_lock_script = Script::try_from(entry_bytes.as_slice()).map_err(to_resolve_err)?;

    let rebuilt_plog = log::Builder::new()
        .with_vlad(vlad)
        .with_first_lock(&first_lock_script)
        .with_entries(&entry_chain.entries)
        .with_head(head_cid)
        .with_foot(&entry_chain.foot_cid)
        .try_build()
        .map_err(to_resolve_err)?;

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
                return Err(ResolveError::VerificationError(e.to_string()));
            }
        }
    }

    Ok(ResolvedPlog {
        log: rebuilt_plog,
        verification_counts,
    })
}
