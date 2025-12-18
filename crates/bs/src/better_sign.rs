// SPDX-License-Identifier: FSL-1.1
//! The [`BetterSign`] struct provides an encapsulated interface to provenance log operations.
//!
//! This module offers a clean, preferred API compared to directly using the functional
//! `open_plog` and `update_plog` functions.
use crate::{
    config::asynchronous::{KeyManager, MultiSigner},
    error::{BsCompatibleError, Error},
    ops::{open, update},
};
use provenance_log::{entry::Entry, Log};

/// A BetterSign instance that encapsulates a provenance log with its key manager and signer.
///
/// This struct provides an ergonomic API for working with provenance logs by keeping
/// the log, key manager, and signer together as a single unit.
#[derive(Debug)]
pub struct BetterSign<KM, S, E = Error> {
    plog: Log,
    key_manager: KM,
    signer: S,
    _phantom: std::marker::PhantomData<E>,
}

impl<KM, S, E> BetterSign<KM, S, E> {
    /// Create a BetterSign instance from existing parts.
    ///
    /// This is useful when you already have a plog and want to wrap it with key management.
    pub fn from_parts(plog: Log, key_manager: KM, signer: S) -> Self {
        Self {
            plog,
            key_manager,
            signer,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Get a reference to the provenance [Log].
    pub fn plog(&self) -> &Log {
        &self.plog
    }

    /// Get a mutable reference to the provenance [Log].
    pub fn plog_mut(&mut self) -> &mut Log {
        &mut self.plog
    }

    /// Get a reference to the key manager.
    pub fn key_manager(&self) -> &KM {
        &self.key_manager
    }

    /// Get a reference to the signer.
    pub fn signer(&self) -> &S {
        &self.signer
    }

    /// Consume self and return the provenance log.
    pub fn into_plog(self) -> Log {
        self.plog
    }

    /// Consume self and return all components.
    pub fn into_parts(self) -> (Log, KM, S) {
        (self.plog, self.key_manager, self.signer)
    }
}

impl<KM, S, E> BetterSign<KM, S, E>
where
    E: BsCompatibleError + Send,
    KM: KeyManager<E>,
    S: MultiSigner<E>,
{
    /// Create a new BetterSign instance with the given configuration.
    pub async fn new(config: open::Config, key_manager: KM, signer: S) -> Result<Self, E> {
        let plog = open::open_plog_core(&config, &key_manager, &signer).await?;
        Ok(Self {
            plog,
            key_manager,
            signer,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Update the provenance log with new operations.
    pub async fn update(&mut self, config: update::Config) -> Result<Entry, E> {
        update::update_plog_core(&mut self.plog, &config, &self.key_manager, &self.signer).await?;
        // Return a clone of the last entry (the one we just added)
        Ok(self
            .plog
            .entries
            .get(&self.plog.head)
            .expect("Head entry should exist")
            .clone())
    }
}

#[cfg(feature = "sync")]
impl<KM, S, E> BetterSign<KM, S, E>
where
    E: BsCompatibleError + Send,
    KM: KeyManager<E>,
    S: MultiSigner<E>,
{
    /// Synchronously create a new BetterSign instance with the given configuration.
    ///
    /// This blocks on the async `new` method using `futures::executor::block_on`.
    ///
    /// # Errors
    ///
    /// Returns an error if the provenance log creation fails.
    pub fn new_sync(config: open::Config, key_manager: KM, signer: S) -> Result<Self, E> {
        futures::executor::block_on(Self::new(config, key_manager, signer))
    }

    /// Synchronously update the provenance log with new operations.
    ///
    /// This blocks on the async `update` method using `futures::executor::block_on`.
    ///
    /// # Errors
    ///
    /// Returns an error if the update operation fails.
    pub fn update_sync(&mut self, config: update::Config) -> Result<Entry, E> {
        futures::executor::block_on(self.update(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::vlad::FirstEntryKeyParams;
    use crate::params::{anykey::PubkeyParams, vlad::VladParams};
    use bs_wallets::memory::InMemoryKeyManager;
    use multicodec::Codec;
    use provenance_log::key::key_paths::ValidatedKeyParams;
    use provenance_log::{Key, Script};

    #[tokio::test]
    async fn test_better_sign_new() {
        let config = open::Config::builder()
            .vlad(VladParams::default())
            .pubkey(
                PubkeyParams::builder()
                    .codec(Codec::Ed25519Priv)
                    .build()
                    .into(),
            )
            .entrykey(
                FirstEntryKeyParams::builder()
                    .codec(Codec::Ed25519Priv)
                    .build()
                    .into(),
            )
            .lock(Script::Code(
                Key::default(),
                "check_signature(\"/pubkey\", \"/entry/\")".to_string(),
            ))
            .unlock(Script::Code(
                Key::default(),
                "push(\"/entry/\"); push(\"/entry/proof\")".to_string(),
            ))
            .build();

        let key_manager = InMemoryKeyManager::<Error>::default();
        let signer = key_manager.clone();

        let bs = BetterSign::new(config, key_manager, signer)
            .await
            .expect("Failed to create BetterSign");

        // Verify the plog was created
        assert!(!bs.plog().entries.is_empty());
        assert!(bs.plog().verify().count() > 0);
    }

    #[tokio::test]
    async fn test_better_sign_update() {
        let open_config = open::Config::builder()
            .vlad(VladParams::default())
            .pubkey(
                PubkeyParams::builder()
                    .codec(Codec::Ed25519Priv)
                    .build()
                    .into(),
            )
            .entrykey(
                FirstEntryKeyParams::builder()
                    .codec(Codec::Ed25519Priv)
                    .build()
                    .into(),
            )
            .lock(Script::Code(
                Key::default(),
                "check_signature(\"/pubkey\", \"/entry/\")".to_string(),
            ))
            .unlock(Script::Code(
                Key::default(),
                "push(\"/entry/\"); push(\"/entry/proof\")".to_string(),
            ))
            .build();

        let key_manager = InMemoryKeyManager::<Error>::default();
        let signer = key_manager.clone();

        let mut bs = BetterSign::new(open_config, key_manager, signer)
            .await
            .expect("Failed to create BetterSign");

        let initial_entry_count = bs.plog().entries.len();

        // Update the plog
        let update_config = update::Config::builder()
            .unlock(Script::Code(
                Key::default(),
                "push(\"/entry/\"); push(\"/entry/proof\")".to_string(),
            ))
            .entry_signing_key(PubkeyParams::KEY_PATH.into())
            .build();

        let entry = bs
            .update(update_config)
            .await
            .expect("Failed to update plog");

        // Verify a new entry was added
        assert_eq!(bs.plog().entries.len(), initial_entry_count + 1);
        assert_eq!(bs.plog().head, entry.cid());
    }

    #[cfg(feature = "sync")]
    #[test]
    fn test_better_sign_sync() {
        let config = open::Config::builder()
            .vlad(VladParams::default())
            .pubkey(
                PubkeyParams::builder()
                    .codec(Codec::Ed25519Priv)
                    .build()
                    .into(),
            )
            .entrykey(
                FirstEntryKeyParams::builder()
                    .codec(Codec::Ed25519Priv)
                    .build()
                    .into(),
            )
            .lock(Script::Code(
                Key::default(),
                "check_signature(\"/pubkey\", \"/entry/\")".to_string(),
            ))
            .unlock(Script::Code(
                Key::default(),
                "push(\"/entry/\"); push(\"/entry/proof\")".to_string(),
            ))
            .build();

        let key_manager = InMemoryKeyManager::<Error>::default();
        let signer = key_manager.clone();

        let bs =
            BetterSign::new_sync(config, key_manager, signer).expect("Failed to create BetterSign");

        // Verify the plog was created
        assert!(!bs.plog().entries.is_empty());
    }
}
