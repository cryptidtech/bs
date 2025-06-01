//! Key Parameters for Operations

use super::*;

use bon::Builder;
use key_params_builder::SetKeyPath;
use multicodec::Codec;
use std::convert::TryFrom;
use std::ops::Deref;

/// A validated key path that is guaranteed to be valid.
///
/// Can only be created through the `const_assert_valid_key!` macro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedKeyPath(pub(crate) &'static str);

impl ValidatedKeyPath {
    /// Create a new validated key path.
    pub const fn new(path: &'static str) -> Self {
        ValidatedKeyPath(path)
    }

    /// Return the key path as a string slice.
    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

// Add Deref implementation
impl Deref for ValidatedKeyPath {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

// Implement TryFrom<&ValidatedKeyPath> for Key
impl<'a> TryFrom<&'a ValidatedKeyPath> for Key {
    type Error = <Key as TryFrom<&'a str>>::Error;

    fn try_from(value: &'a ValidatedKeyPath) -> Result<Self, Self::Error> {
        Key::try_from(value.as_str())
    }
}

// Implement TryFrom<ValidatedKeyPath> for Key
impl From<ValidatedKeyPath> for Key {
    fn from(value: ValidatedKeyPath) -> Self {
        // Safe to unwrap since ValidatedKeyPath is guaranteed to be valid at compile time
        Key::try_from(value.as_str()).unwrap()
    }
}

/// Create a validated key path, ensuring it's valid at compile time.
#[macro_export]
macro_rules! const_assert_valid_key {
    ($path:expr) => {{
        const _: () = {
            $crate::key::validate_key_path($path);
        };
        ValidatedKeyPath::new($path)
    }};
}

/// Generic Key operation parameters for key generation operations.
///
/// This type provides a generic way to define parameters for any key type based on
/// a path that identifies the key. It contains codec, threshold, limit, and revoke settings.
///
/// # Example
///
/// ```rust
/// use multicodec::Codec;
/// use provenance_log::key::key_paths::KeyParamsType;
/// use provenance_log::const_assert_valid_key;
/// use provenance_log::key::key_paths::ValidatedKeyPath;
///
/// // Define predefined types
/// struct PubkeyParams;
/// impl KeyParamsType for PubkeyParams {
///     const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/pubkey");
/// }
///
/// // Create parameters with explicit settings
/// let pubkey_params = PubkeyParams::builder()
///     .codec(Codec::Ed25519Priv)
///     .threshold(1)
///     .limit(1)
///     .revoke(false)
///     .build();
/// ```
#[derive(Builder, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyParams {
    /// Path identifying the key
    key_path: Key,

    /// Codec used for the key
    // #[builder(default = Codec::Ed25519Priv)]
    codec: Codec,

    /// Signature threshold
    #[builder(default = 1)]
    threshold: usize,

    /// Key usage limit
    #[builder(default = 1)]
    limit: usize,

    /// Whether to revoke previous key
    #[builder(default = false)]
    revoke: bool,
}

impl KeyParams {
    /// Access the key path string.
    pub fn key_path(&self) -> &Key {
        &self.key_path
    }

    /// Returns the [Codec] used for the key.
    pub fn codec(&self) -> Codec {
        self.codec
    }

    /// Returns the threshold for the key.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Returns the limit for the key.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Returns the revoke flag for the key.
    pub fn revoke(&self) -> bool {
        self.revoke
    }
}

/// Trait for types that define a specific key path.
///
/// This trait is used to create specific key parameter types that
/// have a predefined KEY_PATH constant.
pub trait KeyParamsType {
    /// The validated key path used for this type.
    const KEY_PATH: ValidatedKeyPath;

    /// Helper method to get a Key from the KEY_PATH.
    ///
    /// # Example
    /// ```rust
    /// use provenance_log::key::key_paths::{KeyParamsType, ValidatedKeyPath};
    /// use provenance_log::const_assert_valid_key;
    /// use provenance_log::Key;
    ///
    /// pub struct MyKeyType;
    /// impl KeyParamsType for MyKeyType {
    ///    const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/mykey");
    /// }
    ///
    /// let key: Key = MyKeyType::key();
    /// assert_eq!(key, Key::try_from("/mykey").unwrap());
    /// ```   
    fn key() -> Key {
        Key::try_from(&Self::KEY_PATH).unwrap()
    }

    /// Creates a KeyParamsBuilder for this key type.
    ///
    /// This method returns a builder that you can use to customize
    /// the parameters for this key type.
    fn builder() -> KeyParamsBuilder<SetKeyPath> {
        Pather::builder()
            .kpath(Self::KEY_PATH.into())
            .build()
            .into()
    }
}

/// Intermediate struct to build KeyParams from a Pather.
#[derive(Builder, Clone)]
struct Pather {
    kpath: Key,
}

// Pather to KeyParams conversion
impl From<Pather> for KeyParamsBuilder<SetKeyPath> {
    fn from(pather: Pather) -> Self {
        KeyParams::builder().key_path(pather.kpath.clone())
    }
}

/// Blanket implementation to convert any type implementing `KeyParamsType` into a `Key`.
impl<T: KeyParamsType> From<T> for Key {
    fn from(_: T) -> Self {
        T::key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_params() {
        pub struct PubkeyParams;

        impl KeyParamsType for PubkeyParams {
            const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/pubkey");
        }

        let params = PubkeyParams::builder()
            .codec(Codec::Ed25519Priv)
            .threshold(1)
            .limit(1)
            .revoke(false)
            .build();

        assert_eq!(params.key_path().to_string(), "/pubkey");
        assert_eq!(params.codec(), Codec::Ed25519Priv);
        assert_eq!(params.threshold(), 1);
        assert_eq!(params.limit(), 1);
        assert!(!params.revoke());
    }

    #[test]
    fn test_explicit_builder() {
        let params = KeyParams::builder()
            .key_path(Key::try_from("/test").unwrap())
            .codec(Codec::Ed25519Priv)
            .threshold(3)
            .limit(5)
            .revoke(true)
            .build();

        assert_eq!(params.key_path(), &Key::try_from("/test").unwrap());
        assert_eq!(params.codec(), Codec::Ed25519Priv);
        assert_eq!(params.threshold(), 3);
        assert_eq!(params.limit(), 5);
        assert!(params.revoke());
    }
}

#[cfg(test)]
mod invalid_path_tests {
    use super::*;

    // This module tests compile-time validation - no actual test code is run

    #[test]
    fn test_key_params_validation_compiles() {
        // This should compile fine
        struct ValidKey;

        impl KeyParamsType for ValidKey {
            const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/valid/path");
        }

        let _ = ValidKey::builder()
            .codec(Codec::Ed25519Priv)
            .threshold(1)
            .limit(10)
            .revoke(false)
            .build();

        // The following would fail to compile if uncommented:
        /*
        struct InvalidKey;

        impl KeyParamsType for InvalidKey {
            const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("invalid-no-leading-slash");
        }

        */
    }
}
