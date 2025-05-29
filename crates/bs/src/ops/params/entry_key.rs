//! EntryKey Parameters for Operations
use crate::ops::update::OpParams;
use multicodec::Codec;
use provenance_log::Key;

/// Entry Key operation parameters, made up of key, codec, threshold, limit, and revoke flag.
///
/// # Example
///
/// ```rust
/// use bs::ops::params::entry_key::EntryKeyParams;
/// use multicodec::Codec;
/// use provenance_log::Key;
///
/// let params = EntryKeyParams::builder()
///     .codec(Codec::Ed25519Priv)
///     .threshold(1)
///     .limit(1)
///     .revoke(false)
///     .build();
///
/// let params: EntryKeyParams = params.into();
/// ```
#[derive(Debug, Clone, bon::Builder)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EntryKeyParams {
    codec: Codec,
    threshold: usize,
    limit: usize,
    revoke: bool,
}

impl Default for EntryKeyParams {
    fn default() -> Self {
        Self {
            codec: Codec::Ed25519Priv,
            threshold: 1,
            limit: 1,
            revoke: false,
        }
    }
}

impl EntryKeyParams {
    /// Key path for entry key operations.
    pub const KEY_PATH: &'static str = "/entrykey";

    /// Creates a new instance of `EntryKeyParams`.
    pub fn new(codec: Codec, threshold: usize, limit: usize, revoke: bool) -> Self {
        Self {
            codec,
            threshold,
            limit,
            revoke,
        }
    }
}

impl From<EntryKeyParams> for OpParams {
    fn from(params: EntryKeyParams) -> Self {
        OpParams::KeyGen {
            key: Key::try_from(EntryKeyParams::KEY_PATH).unwrap(),
            codec: params.codec,
            threshold: params.threshold,
            limit: params.limit,
            revoke: params.revoke,
        }
    }
}

/// Returns default entry key parameters.
pub fn default_entrykey_params() -> OpParams {
    EntryKeyParams::default().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::update::OpParams;

    #[test]
    fn test_entrykey_params_conversion() {
        let key = Key::try_from("/test/entry").unwrap();
        let params = EntryKeyParams::new(Codec::Ed25519Priv, 2, 10, false);
        let op_params: OpParams = params.into();

        if let OpParams::KeyGen {
            key: k,
            codec,
            threshold,
            limit,
            revoke,
        } = op_params
        {
            assert_eq!(k, Key::try_from(EntryKeyParams::KEY_PATH).unwrap());
            assert_eq!(codec, Codec::Ed25519Priv);
            assert_eq!(threshold, 2);
            assert_eq!(limit, 10);
            assert!(!revoke);
        } else {
            panic!("Expected OpParams::KeyGen");
        }
    }

    #[test]
    fn test_entrykey_params_builder() {
        let params = EntryKeyParams::builder()
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

    #[test]
    fn test_default_entrykey_params() {
        let op_params = default_entrykey_params();

        if let OpParams::KeyGen {
            key,
            codec,
            threshold,
            limit,
            revoke,
        } = op_params
        {
            assert_eq!(key, Key::try_from(EntryKeyParams::KEY_PATH).unwrap());
            assert_eq!(codec, Codec::Ed25519Priv);
            assert_eq!(threshold, 1);
            assert_eq!(limit, 1);
            assert!(!revoke);
        } else {
            panic!("Expected OpParams::KeyGen");
        }
    }
}
