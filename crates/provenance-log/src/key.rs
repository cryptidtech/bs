// SPDX-License-Identifier: FSL-1.1
pub mod key_paths;

use crate::{error::KeyError, Error};
use multibase::Base;
use multitrait::TryDecodeFrom;
use multiutil::{EncodingInfo, Varbytes, VarbytesIter};
use std::fmt;
use tracing::info;

/// The separator for the parts of a key.
pub const KEY_SEPARATOR: char = '/';

/// The keys used to reference values in a Pairs storage.
///
/// These form a path of namespaces each part separated by the separator "/" and they come in two flavors:
/// - A **branch** is a key-path that ends with the separator: "/foo/bar/baz/"
/// - A **leaf** is a key-path that does not end with the separator: "/foo/bar/baz"
///
/// Branches identify a namespace full of leaves and a leaf identifies a single value.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Key {
    parts: Vec<String>,
    s: String, // holds the "rendered" string so we can return a &str
}

impl Key {
    /// Returns true if this key is a branch.
    pub fn is_branch(&self) -> bool {
        self.parts.last().unwrap().is_empty()
    }

    /// Returns true if this key is a leaf.
    pub fn is_leaf(&self) -> bool {
        !self.parts.last().unwrap().is_empty()
    }

    /// Adds a key-path to this key.
    ///
    /// The current key must be a branch (ending with a separator) for this operation to succeed.
    ///
    /// # Errors
    ///
    /// Returns `KeyError::NotABranch` if the current key is not a branch.
    /// Returns error if the provided string is not a valid key.
    pub fn push<S: AsRef<str>>(&mut self, s: S) -> Result<(), Error> {
        if !self.is_branch() {
            return Err(KeyError::NotABranch.into());
        }
        let moar = Self::try_from(s.as_ref())?;
        let _ = self.parts.pop();
        self.parts.append(
            &mut moar.parts[1..]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        );
        self.s = self.parts.join(&KEY_SEPARATOR.to_string());
        Ok(())
    }

    /// Determines if this key is a parent of (or equal to) the other key.
    ///
    /// - If this path is a leaf, returns true if the passed-in path is exactly the same.
    /// - If this path is a branch, returns true if the passed-in path starts with this path.
    pub fn parent_of(&self, other: &Self) -> bool {
        info!(
            "\t{} is a {}",
            self,
            if self.is_leaf() { "leaf" } else { "branch" }
        );
        if self.is_leaf() {
            self == other
        } else {
            let mut self_parts = Vec::default();
            let mut itr = self.parts.iter();
            itr.next(); // skip the first ""
            for p in itr {
                self_parts.push("/".to_string());
                if !p.is_empty() {
                    self_parts.push(p.clone());
                }
            }

            let mut other_parts = Vec::default();
            let mut itr = other.parts.iter();
            itr.next(); // skip the first ""
            for p in itr {
                other_parts.push("/".to_string());
                if !p.is_empty() {
                    other_parts.push(p.clone());
                }
            }

            info!(
                "\t{:?} {} with {:?}",
                other_parts,
                if other_parts.starts_with(&self_parts) {
                    "starts"
                } else {
                    "does not start"
                },
                self_parts
            );
            other_parts.starts_with(&self_parts)
        }
    }

    /// Returns the number of parts in the key.
    pub fn len(&self) -> usize {
        match self.parts.len() {
            0 => 0,
            len => {
                if self.is_branch() {
                    len - 2
                } else {
                    len - 1
                }
            }
        }
    }

    /// Returns true if the key has zero length.
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Returns the branch part of the key.
    ///
    /// If this key is already a branch or is empty, returns a clone of itself.
    /// If this key is a leaf, returns a branch version by adding a trailing separator.
    pub fn branch(&self) -> Self {
        if self.is_branch() || self.is_empty() {
            self.clone()
        } else {
            let mut parts = self.parts.clone();
            let _ = parts.pop();
            parts.push("".to_string());
            let s = parts.join(&KEY_SEPARATOR.to_string());
            Self { parts, s }
        }
    }

    /// Returns the longest common branch between this and the other Key.
    ///
    /// This finds the common ancestor path between two keys.
    pub fn longest_common_branch(&self, rhs: &Key) -> Self {
        let lhs = self.branch();
        let rhs = rhs.branch();
        let mut parts = Vec::default();
        let itr = lhs.parts.iter().zip(rhs.parts.iter());
        for (l, r) in itr {
            if l == r {
                parts.push(l.clone());
            } else {
                break;
            }
        }

        match parts.len() {
            0 => {
                parts.push("".to_string());
                parts.push("".to_string());
            }
            1 => {
                parts.push("".to_string());
            }
            _ => {
                if parts.last() != Some(&"".to_string()) {
                    parts.push("".to_string());
                }
            }
        }

        let s = parts.join(&KEY_SEPARATOR.to_string());
        Self { parts, s }
    }

    /// Returns the key as a string slice.
    pub fn as_str(&self) -> &str {
        self.s.as_str()
    }
}

impl Default for Key {
    fn default() -> Self {
        let parts = vec!["".to_string(), "".to_string()];
        let s = parts.join(&KEY_SEPARATOR.to_string());
        Self { parts, s }
    }
}

impl EncodingInfo for Key {
    /// Returns the preferred string encoding.
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    /// Returns the encoding for this key.
    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl From<Key> for Vec<u8> {
    fn from(val: Key) -> Self {
        let mut v = Vec::default();
        // convert the path to a string and encode it as varbytes
        v.extend(&mut VarbytesIter::from(val.to_string().as_bytes()));
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for Key {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Error> {
        let (key, _) = Self::try_decode_from(bytes)?;
        Ok(key)
    }
}

impl<'a> TryDecodeFrom<'a> for Key {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (s, ptr) = Varbytes::try_decode_from(bytes)?;
        let s = String::from_utf8(s.to_inner())?;
        let k = Self::try_from(s)?;
        Ok((k, ptr))
    }
}

impl TryFrom<&str> for Key {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::try_from(s.to_string())
    }
}

impl TryFrom<String> for Key {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.is_empty() {
            return Err(KeyError::EmptyKey.into());
        }
        let filtered = {
            let mut prev = KEY_SEPARATOR;
            let mut filtered = String::default();
            for (i, c) in s.chars().enumerate() {
                match i {
                    0 => {
                        if c != KEY_SEPARATOR {
                            return Err(KeyError::MissingRootSeparator(s).into());
                        }
                        filtered.push(c);
                    }
                    // eliminate runs of the separator char '///' becomes '/'
                    _ if c == KEY_SEPARATOR => {
                        if c != prev {
                            filtered.push(c);
                            prev = c;
                        }
                    }
                    _ => {
                        filtered.push(c);
                        prev = c;
                    }
                }
            }
            filtered
        };
        let parts = filtered
            .split(KEY_SEPARATOR)
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let s = parts.join(&KEY_SEPARATOR.to_string());
        Ok(Self { parts, s })
    }
}

impl AsRef<str> for Key {
    fn as_ref(&self) -> &str {
        self.s.as_str()
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.parts.join(&KEY_SEPARATOR.to_string()))
    }
}

/// A minimal const validator for [Key] path strings, for use in const contexts.
/// Will panic at compile time if the string is invalid.
///
/// This validator checks:
/// - non-empty
/// - must start with '/'
/// - no double slashes '//' (no empty path segments except at the end)
///
/// # Example
/// ```rust
/// use provenance_log::key::validate_key_path;
///
/// // Valid key paths
/// validate_key_path("/foo/bar/baz/"); // branch
/// validate_key_path("/foo/bar/baz");  // leaf
///
/// // The following would panic at compile time:
/// // validate_key_path("/foo//bar/baz");  // double slash
/// // validate_key_path("foo/bar/baz");    // no leading slash
/// // validate_key_path("");               // empty string
///
/// // Example trait for compile-time key path verification
/// pub trait HasKeyPath {
///     const KEY_PATH: &'static str;
///     // This will cause a compile error if KEY_PATH is not valid
///     const VALIDATE: () = {
///         validate_key_path(Self::KEY_PATH);
///     };
/// }
/// ```
///
/// # Panics
/// This function will panic if the string does not meet the [Key] criteria.
pub const fn validate_key_path(s: &str) {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        panic!("Key must not be empty");
    }
    if bytes[0] != b'/' {
        panic!("Key must start with '/'");
    }
    // Check for double slashes anywhere except possibly at the end
    let mut i = 1;
    while i < bytes.len() {
        if bytes[i] == b'/' && bytes[i - 1] == b'/' {
            panic!("Key must not contain '//' (double slash)");
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;
    use tracing::{span, Level};

    #[test]
    #[should_panic]
    fn test_empty_key() {
        Key::try_from("").unwrap();
    }

    #[test]
    #[should_panic]
    fn test_bad_key() {
        Key::try_from("foo/bar").unwrap();
    }

    #[test]
    fn test_default() {
        let _s = span!(Level::INFO, "test_default").entered();
        let k = Key::default();
        assert!(k.is_branch());
        assert!(!k.is_leaf());
        assert_eq!(0, k.len());
        assert_eq!(format!("{}", k), "/".to_string());
    }

    #[test]
    fn test_branch() {
        let _s = span!(Level::INFO, "test_branch").entered();
        let k = Key::try_from("/foo/bar/baz/").unwrap();
        assert!(k.is_branch());
        assert!(!k.is_leaf());
        assert_eq!(3, k.len());
        assert_eq!(format!("{}", k), "/foo/bar/baz/".to_string());
        assert_eq!(format!("{}", k.branch()), "/foo/bar/baz/".to_string());
        assert_eq!(3, k.branch().len());
    }

    #[test]
    fn test_leaf() {
        let _s = span!(Level::INFO, "test_leaf").entered();
        let k = Key::try_from("/foo/bar/baz").unwrap();
        assert!(!k.is_branch());
        assert!(k.is_leaf());
        assert_eq!(3, k.len());
        assert_eq!(format!("{}", k), "/foo/bar/baz".to_string());
        assert_eq!(format!("{}", k.branch()), "/foo/bar/".to_string());
        assert_eq!(2, k.branch().len());
    }

    #[test]
    fn longest_branch_one() {
        let _s = span!(Level::INFO, "longest_branch_one").entered();
        let l = Key::try_from("/foo/bar/baz").unwrap();
        let r = Key::try_from("/foo/bar").unwrap();
        let mk = l.longest_common_branch(&r);
        assert!(mk.is_branch());
        assert_eq!(1, mk.len());
        assert_eq!(format!("{}", mk), "/foo/".to_string());
    }

    #[test]
    fn longest_branch_two() {
        let _s = span!(Level::INFO, "longest_branch_two").entered();
        let l = Key::try_from("/foo/bar/baz").unwrap();
        let r = Key::try_from("/blah/boo").unwrap();
        let mk = l.longest_common_branch(&r);
        assert!(mk.is_branch());
        assert_eq!(0, mk.len());
        assert_eq!(format!("{}", mk), "/".to_string());
    }

    #[test]
    fn longest_branch_three() {
        let _s = span!(Level::INFO, "longest_branch_three").entered();
        let l = Key::try_from("/").unwrap();
        let r = Key::try_from("/blah/boo").unwrap();
        let mk = l.longest_common_branch(&r);
        assert!(mk.is_branch());
        assert_eq!(0, mk.len());
        assert_eq!(format!("{}", mk), "/".to_string());
    }

    #[test]
    fn longest_branch_four() {
        let _s = span!(Level::INFO, "longest_branch_four").entered();
        let l = Key::try_from("/").unwrap();
        let r = Key::try_from("/").unwrap();
        let mk = l.longest_common_branch(&r);
        assert!(mk.is_branch());
        assert_eq!(0, mk.len());
        assert_eq!(format!("{}", mk), "/".to_string());
    }

    #[test]
    fn longest_branch_five() {
        let _s = span!(Level::INFO, "longest_branch_five").entered();
        let l = Key::try_from("/foo/bar/baz/blah/").unwrap();
        let r = Key::try_from("/foo/bar/baz/blah/").unwrap();
        let mk = l.longest_common_branch(&r);
        assert!(mk.is_branch());
        assert_eq!(4, mk.len());
        assert_eq!(format!("{}", mk), "/foo/bar/baz/blah/".to_string());
    }

    #[test]
    fn sort_keys() {
        let _s = span!(Level::INFO, "sort_keys").entered();
        let mut v: Vec<Key> = vec![
            Key::try_from("/bar/").unwrap(),
            Key::try_from("/").unwrap(),
            Key::try_from("/bar/").unwrap(),
            Key::try_from("/foo").unwrap(),
        ];
        v.sort();
        for k in v {
            println!("{}", k);
        }
    }

    #[test]
    #[should_panic]
    fn push_to_leaf() {
        let mut l = Key::try_from("/foo/bar/baz").unwrap();
        l.push("/blah").unwrap();
    }

    #[test]
    #[should_panic]
    fn push_invalid_key() {
        let mut k = Key::try_from("/foo/bar/").unwrap();
        k.push("baz").unwrap();
    }

    #[test]
    fn push_leaf() {
        let _s = span!(Level::INFO, "push_leaf").entered();
        let mut b = Key::try_from("/foo/bar/").unwrap();
        b.push("/baz").unwrap();
        assert!(b.is_leaf());
        assert_eq!(format!("{}", b), "/foo/bar/baz".to_string());
    }

    #[test]
    fn push_branch() {
        let _s = span!(Level::INFO, "push_branch").entered();
        let mut b = Key::try_from("/foo/bar/").unwrap();
        b.push("/baz/").unwrap();
        assert!(b.is_branch());
        assert_eq!(format!("{}", b), "/foo/bar/baz/".to_string());
    }

    #[test]
    fn test_as_ref() {
        let _s = span!(Level::INFO, "test_as_ref").entered();
        let b = Key::try_from("/foo/bar").unwrap();
        assert_eq!(b.as_ref(), "/foo/bar");
    }
}
