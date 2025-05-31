//! Generic Key Parameters for Operations

use super::*;

use multicodec::Codec;
use std::convert::TryFrom;
use std::ops::Deref;

/// A validated key path that is guaranteed to be valid.
///
/// Can only be created through the `const_assert_valid_key!` macro.
pub struct ValidatedKeyPath(pub(crate) &'static str);

impl ValidatedKeyPath {
    /// Create a new validated key path.
    pub const fn new(path: &'static str) -> Self {
        ValidatedKeyPath(path)
    }
}

// Add Deref implementation
impl Deref for ValidatedKeyPath {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

// Add AsRef<str> implementation
impl AsRef<str> for ValidatedKeyPath {
    fn as_ref(&self) -> &str {
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

impl ValidatedKeyPath {
    /// Return the key path as a string slice.
    pub const fn as_str(&self) -> &'static str {
        self.0
    }
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
/// use provenance_log::key::util::{KeyParams, KeyParamsType};
/// use provenance_log::const_assert_valid_key;
/// use provenance_log::key::util::ValidatedKeyPath;
///
/// // Define predefined types
/// struct PubkeyParams;
/// impl KeyParamsType for PubkeyParams {
///     const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/pubkey");
/// }
///
/// struct EntryKeyParams;
/// impl KeyParamsType for EntryKeyParams {
///     const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/entry");
/// }
///
/// // Using predefined types
/// let pubkey_params = PubkeyParams::default_params();
/// let entry_params = EntryKeyParams::default_params();
///
/// // Or create your own key type
/// let custom_params = KeyParams::with_key_path("/my_custom_key")
///     .codec(Codec::Ed25519Priv)
///     .threshold(2)
///     .limit(10)
///     .revoke(false)
///     .build();
/// ```
///
/// # Creating Custom Key Types
///
/// You can easily create your own key parameter types by using the `KeyParamsType` trait:
///
/// ```rust
/// use provenance_log::key::util::{KeyParams, KeyParamsType};
/// use provenance_log::key::util::ValidatedKeyPath;
/// use provenance_log::const_assert_valid_key;
///
/// pub struct MyCustomKeyParams;
///
/// impl KeyParamsType for MyCustomKeyParams {
///     const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/my_special_key");
/// }
///
/// // Create parameters with defaults
/// let params = MyCustomKeyParams::default_params();
///
/// // Or customize them
/// let custom = MyCustomKeyParams::params()
///     .threshold(3)
///     .build();
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyParams {
    key_path: String,
    codec: Codec,
    threshold: usize,
    limit: usize,
    revoke: bool,
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
    /// use provenance_log::key::util::{KeyParamsType, ValidatedKeyPath};
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
    /// This method returns a builder that can be used to customize
    /// the parameters for this key type.
    fn params() -> KeyParamsBuilder {
        KeyParams::with_key_path(Self::KEY_PATH.as_str())
    }

    /// Returns default parameters for this key type.
    ///
    /// This method creates a KeyParams object with default settings
    /// for the specific key path defined by this type.
    fn default_params() -> KeyParams {
        Self::params().build()
    }
}

/// Blanket implementation to convert any type implementing `KeyParamsType` into a `Key`.
///
/// This provides a convenient way to get a `Key` directly from a key parameter type.
///
/// # Example
///
/// ```rust
/// use provenance_log::Key;
/// use provenance_log::key::util::{KeyParamsType, ValidatedKeyPath};
/// use provenance_log::const_assert_valid_key;
///
/// // Define a custom key type
/// pub struct MyBranchKey;
///
/// impl KeyParamsType for MyBranchKey {
///     const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/branch/main");
///     
///     // Rest of the implementation is provided by default methods
/// }
///
/// // Convert directly to Key with into()
/// let key: Key = MyBranchKey.into();
///
/// // Define another type for the example
/// pub struct PubkeyParams;
/// impl KeyParamsType for PubkeyParams {
///     const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("/pubkey");
/// }
///
/// // Also works with predefined types
/// let pubkey: Key = PubkeyParams.into();
///
/// // This is equivalent to using the key() method
/// assert_eq!(Key::from(MyBranchKey), MyBranchKey::key());
/// ```
impl<T: KeyParamsType> From<T> for Key {
    fn from(_: T) -> Self {
        T::key()
    }
}

impl Default for KeyParams {
    fn default() -> Self {
        Self {
            key_path: "/key".to_string(), // Default path
            codec: Codec::Ed25519Priv,
            threshold: 1,
            limit: 1,
            revoke: false,
        }
    }
}

/// Builder for [KeyParams].
///
/// Provides a fluent interface for creating customized KeyParams objects.
pub struct KeyParamsBuilder {
    params: KeyParams,
}

impl KeyParams {
    /// Create a builder with the specified key path.
    pub fn with_key_path(key_path: &str) -> KeyParamsBuilder {
        KeyParamsBuilder {
            params: Self {
                key_path: key_path.to_string(),
                codec: Codec::Ed25519Priv,
                threshold: 1,
                limit: 1,
                revoke: false,
            },
        }
    }

    /// Returns the key path for this parameters object.
    pub fn key_path(&self) -> &str {
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

impl KeyParamsBuilder {
    /// Set the codec for the key.
    pub fn codec(mut self, codec: Codec) -> Self {
        self.params.codec = codec;
        self
    }

    /// Set the threshold for the key.
    pub fn threshold(mut self, threshold: usize) -> Self {
        self.params.threshold = threshold;
        self
    }

    /// Set the limit for the key.
    pub fn limit(mut self, limit: usize) -> Self {
        self.params.limit = limit;
        self
    }

    /// Set the revoke flag for the key.
    pub fn revoke(mut self, revoke: bool) -> Self {
        self.params.revoke = revoke;
        self
    }

    /// Build the KeyParams.
    pub fn build(self) -> KeyParams {
        self.params
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

        let params = PubkeyParams::default_params();
        assert_eq!(params.key_path, "/pubkey");
        assert_eq!(params.key_path, PubkeyParams::KEY_PATH.as_str());
        assert_eq!("/pubkey", PubkeyParams::KEY_PATH.as_str());
        assert_eq!(params.key_path, PubkeyParams::KEY_PATH.deref());
        assert_eq!(params.key_path, *PubkeyParams::KEY_PATH);
        assert_eq!(params.threshold, 1);
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

        let _ = ValidKey::default_params();

        // The following would fail to compile if uncommented:
        /*
        struct InvalidKey;

        impl KeyParamsType for InvalidKey {
            const KEY_PATH: ValidatedKeyPath = const_assert_valid_key!("invalid-no-leading-slash");
        }

        let _ = InvalidKey::default_params();
        */
    }
}
