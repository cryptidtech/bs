//! PublicKey Parameters for Operatione
use crate::ops::update::OpParams;
use multicodec::Codec;
use provenance_log::Key;

/// Public Key operation parameters, made up of [Codec], threshold, limit, and revoke flag.
///
/// # Example
///
/// ```rust
/// use bs::ops::params::pubkey::PubkeyParams;
/// use multicodec::Codec;
/// let params = PubkeyParams::builder()
///    .codec(Codec::Sha2256)
///    .threshold(2)
///    .limit(10)
///    .revoke(false)
///    .build();
///
/// let params: PubkeyParams = params.into();
/// ```
#[derive(Debug, Clone, bon::Builder)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PubkeyParams {
    codec: Codec,
    threshold: usize,
    limit: usize,
    revoke: bool,
}

impl PubkeyParams {
    /// Key path
    pub const KEY_PATH: &'static str = "/pubkey";

    /// Creates a new instance of `PubkeyParams`.
    pub fn new(codec: Codec, threshold: usize, limit: usize, revoke: bool) -> Self {
        Self {
            codec,
            threshold,
            limit,
            revoke,
        }
    }
}

impl From<PubkeyParams> for OpParams {
    fn from(params: PubkeyParams) -> Self {
        OpParams::KeyGen {
            key: Key::try_from(PubkeyParams::KEY_PATH).unwrap(),
            codec: params.codec,
            threshold: params.threshold,
            limit: params.limit,
            revoke: params.revoke,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::update::OpParams;

    #[test]
    fn test_pubkey_params_conversion() {
        let params = PubkeyParams::new(Codec::Ed25519Priv, 2, 10, false);
        let op_params: OpParams = params.into();
        assert!(matches!(op_params, OpParams::KeyGen { .. }));
    }

    // test using bon::Builder
    #[test]
    fn test_pubkey_params_builder() {
        let params = PubkeyParams::builder()
            .codec(Codec::Ed25519Priv)
            .threshold(2)
            .limit(10)
            .revoke(false)
            .build();

        assert_eq!(params.codec, Codec::Ed25519Priv);
        assert_eq!(params.threshold, 2);
        assert_eq!(params.limit, 10);
        assert!(!params.revoke);
    }
}
