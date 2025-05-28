//! Basic in-memory wallet implementation.
//! In memory Key manager and signer
use crate::Error;
use bs::config::{Key, Multikey, Multisig};
use bs::ops::params::pubkey::PubkeyParams;
use bs::ops::params::vlad::VladParams;
use bs_traits::{GetKey, Signer, SyncGetKey, SyncSigner};
use multibase::Base;
use multicodec::Codec;
use multihash::EncodedMultihash;
use multikey::{mk, Views as _};

#[derive(Debug, Clone, Default)]
pub(crate) struct InMemoryKeyManager {
    vlad: Option<Multikey>,
    entry_key: Option<Multikey>,
}

impl InMemoryKeyManager {
    /// [Codec] for fingerprint
    pub(crate) const FINGERPRINT_CODEC: Codec = Codec::Sha3256;
    /// [Base] encoding for the fingerprint
    pub(crate) const FINGERPRINT_BASE: Base = Base::Base36Lower;

    /// Returns the vlad key if it exists
    pub fn vlad(&self) -> Option<&Multikey> {
        self.vlad.as_ref()
    }

    /// Returns the entry key if it exists
    pub fn entry_key(&self) -> Option<&Multikey> {
        self.entry_key.as_ref()
    }

    /// Encodes the Multikey to a string representation.
    fn encode(mk: &Multikey) -> Result<String, Error> {
        let fp = mk
            .fingerprint_view()?
            .fingerprint(Self::FINGERPRINT_CODEC)?;
        let ef = EncodedMultihash::new(Self::FINGERPRINT_BASE, fp);
        Ok(ef.to_string())
    }
}

impl GetKey for InMemoryKeyManager {
    type KeyPath = Key;
    type Codec = Codec;
    type Key = Multikey;
    type Error = bs::Error;
}

impl SyncGetKey for InMemoryKeyManager {
    fn get_key<'a>(
        &'a mut self,
        key_path: &'a Self::KeyPath,
        codec: &'a Self::Codec,
        _threshold: usize,
        _limit: usize,
    ) -> Result<Self::Key, Self::Error> {
        tracing::trace!("Key request for {:?}", key_path.to_string());

        let mut rng = rand_core_6::OsRng;
        let mk = mk::Builder::new_from_random_bytes(*codec, &mut rng)?.try_build()?;

        match key_path.to_string().as_str() {
            VladParams::KEY_PATH => {
                // save the public mulitkey for the vlad
                tracing::trace!(
                    "[GENERATE] {}",
                    Self::encode(&mk).expect("Failed to encode generated MK")
                );

                self.vlad = Some(mk.conv_view()?.to_public_key()?);
                tracing::trace!("Vlad key: {:#?}", self.vlad());
            }
            PubkeyParams::KEY_PATH => {
                self.entry_key = Some(mk.clone());
            }
            _ => {}
        }

        Ok(mk)
    }
}

impl Signer for InMemoryKeyManager {
    type Key = Multikey;
    type Signature = Multisig;
    type Error = bs::Error;
}

impl SyncSigner for InMemoryKeyManager {
    fn try_sign(&self, key: &Self::Key, data: &[u8]) -> Result<Self::Signature, Self::Error> {
        let msg = data;
        let combined = false;
        let scheme = None;
        Ok(key.sign_view()?.sign(msg, combined, scheme)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bs_peer::BsPeer;

    #[tokio::test]
    async fn test_in_memory_key_manager() {
        let key_manager = InMemoryKeyManager::default();
        assert!(key_manager.vlad.is_none());
        assert!(key_manager.entry_key.is_none());

        let bs_peer = BsPeer::new(key_manager.clone(), key_manager).await;
    }
}
