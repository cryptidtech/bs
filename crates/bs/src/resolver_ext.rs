//! Extension trait for Resolver to provide VLAD-specific resolution functions
use crate::ops::params::vlad::{FirstEntryKeyParams, VladParams};
use multicid::Cid;
use provenance_log::{
    resolver::{ResolveError, ResolvedPlog, Resolver},
    Entry, Error as PlogError, Key, Script, Value,
};
use std::future::Future;
use std::pin::Pin;

/// Type alias for the future returned by resolve_vlad_first_lock_bytes
pub type FirstLockFuture<'a, R> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, <R as Resolver>::Error>> + Send + 'a>>;

/// Type alias for the future returned by resolve_plog
pub type PlogResolutionFuture<'a, R> =
    Pin<Box<dyn Future<Output = Result<ResolvedPlog, <R as Resolver>::Error>> + Send + 'a>>;

/// Extension trait for [Resolver] to provide VLAD-specific [Entry] resolution functions
///
/// In other words, uses [Resolver] to resolve first lock from an [Entry] and an entire
/// [provenance_log::Log] from a head [Cid]
pub trait ResolverExt: Resolver {
    /// Resolve a [multicid::Vlad]'s first lock [Script] bytes from an [Entry]
    fn resolve_first_lock<'a>(&'a self, entry: &'a Entry) -> FirstLockFuture<'a, Self> {
        Box::pin(async move {
            let binding = entry.vlad();
            let first_lock_cid = binding.cid();

            // Use the type-safe constant for VLAD data path
            let vlad_data_key = VladParams::<FirstEntryKeyParams>::DATA_KEY;

            let value = entry
                .get_value(&Key::try_from(vlad_data_key.as_str())?)
                .ok_or_else(|| {
                    ResolveError::ResolveCidError(format!(
                        "First lock CID not found in entry: {} \n {:?}",
                        first_lock_cid, entry
                    ))
                })?;

            if let Value::Data(bytes) = value {
                Ok(bytes.to_vec())
            } else {
                Err(ResolveError::ParseEntryError(format!(
                    "First lock CID value is not of type Data in entry: {}",
                    first_lock_cid
                ))
                .into())
            }
        })
    }

    /// Given the head [Cid], resolve the [provenance_log::Log] entries,
    /// rebuild the Plog, and verify it.
    fn resolve_plog<'a>(&'a self, head_cid: &'a Cid) -> PlogResolutionFuture<'a, Self>
    where
        Self: Sync,
    {
        Box::pin(async move {
            tracing::debug!("Resolving plog for head CID: {}", head_cid);
            let entry_chain = self.get_entry_chain(head_cid).await?;

            tracing::info!(
                "Retrieved entry chain with {} entries",
                entry_chain.entries.len()
            );

            let entry = if entry_chain.entries.len() == 1 {
                tracing::debug!("Single entry chain - head and foot are the same");
                entry_chain.foot().cloned().unwrap()
            } else {
                tracing::debug!("Multiple entries - resolving foot CID");
                let entry_bytes = self.resolve(&entry_chain.foot_cid).await?;

                tracing::debug!("Foot resolved. Converting to Entry...");
                Entry::try_from(entry_bytes.as_slice())?
            };

            let vlad = entry.vlad();
            let first_lock_cid = vlad.cid();
            tracing::info!("First lock CID: {}", first_lock_cid);

            // Use the new helper method to get first lock bytes
            let first_lock_bytes = self.resolve_first_lock(&entry).await?;
            tracing::debug!("First lock bytes: {:?}", first_lock_bytes);

            let first_lock_script = Script::try_from(first_lock_bytes.as_slice())?;
            tracing::debug!("First lock script built Rebuilt plog");

            let rebuilt_plog = provenance_log::log::Builder::new()
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
                        return Err(
                            PlogError::Log(provenance_log::error::LogError::VerifyFailed(
                                e.to_string(),
                            ))
                            .into(),
                        );
                    }
                }
            }

            Ok(ResolvedPlog {
                log: rebuilt_plog,
                verification_counts,
            })
        })
    }
}

// Implement the extension trait for any type that implements Resolver
impl<T: Resolver + ?Sized> ResolverExt for T {}
