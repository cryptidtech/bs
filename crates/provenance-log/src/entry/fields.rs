//! Field identifiers for the Provenance Log entry

/// Entry field identifiers with type-safe access
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// The entry itself, without the proof
    Entry,
    /// The version of the entry
    Version,
    /// The Vlad for the provenance log
    Vlad,
    /// The previous entry's CID
    Prev,
    /// The Lipmaa link for O(log n) traversal
    Lipmaa,
    /// The sequence number of the entry
    Seqno,
    /// The operations in the entry
    Ops,
    /// The unlock script associated with the entry
    Unlock,
    /// The proof data for the entry, such as a digital signature or zkp
    Proof,
}

impl Field {
    /// Path prefix for all entry fields
    pub const PATH_PREFIX: &'static str = "/entry/";

    /// Path for the Entry field
    pub const ENTRY: &'static str = "/entry/";
    /// Path for the Version field
    pub const VERSION: &'static str = "/entry/version";
    /// Path for the Vlad field
    pub const VLAD: &'static str = "/entry/vlad";
    /// Path for the Prev field
    pub const PREV: &'static str = "/entry/prev";
    /// Path for the Lipmaa field
    pub const LIPMAA: &'static str = "/entry/lipmaa";
    /// Path for the Seqno field
    pub const SEQNO: &'static str = "/entry/seqno";
    /// Path for the Ops field
    pub const OPS: &'static str = "/entry/ops";
    /// Path for the Unlock field
    pub const UNLOCK: &'static str = "/entry/unlock";
    /// Path for the Proof field
    pub const PROOF: &'static str = "/entry/proof";

    /// Convert field to its string representation
    pub const fn as_str(&self) -> &'static str {
        match self {
            Field::Entry => Self::ENTRY,
            Field::Version => Self::VERSION,
            Field::Vlad => Self::VLAD,
            Field::Prev => Self::PREV,
            Field::Lipmaa => Self::LIPMAA,
            Field::Seqno => Self::SEQNO,
            Field::Ops => Self::OPS,
            Field::Unlock => Self::UNLOCK,
            Field::Proof => Self::PROOF,
        }
    }

    /// Get all field identifiers
    pub const fn all() -> [Field; 9] {
        [
            Field::Entry,
            Field::Version,
            Field::Vlad,
            Field::Prev,
            Field::Lipmaa,
            Field::Seqno,
            Field::Ops,
            Field::Unlock,
            Field::Proof,
        ]
    }

    /// Get all field paths as string slices
    pub const fn all_paths() -> [&'static str; 9] {
        [
            Self::ENTRY,
            Self::VERSION,
            Self::VLAD,
            Self::PREV,
            Self::LIPMAA,
            Self::SEQNO,
            Self::OPS,
            Self::UNLOCK,
            Self::PROOF,
        ]
    }
}

impl AsRef<str> for Field {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// A macro to format strings with Field constants
///
/// This macro allows you to use {Field::ENTRY}, {Field::PROOF}, etc. directly in string templates,
/// which will be replaced with the actual string values of those constants.
///
/// # Examples
///
/// ```
/// use provenance_log::entry::Field;
/// use provenance_log::format_with_fields;
/// let unlock_script = format_with_fields!(
///     r#"
///         // push the serialized Entry as the message
///         push("{Field::ENTRY}");
///
///         // push the proof data
///         push("{Field::PROOF}");
///     "#
/// );
/// ```
#[macro_export]
macro_rules! format_with_fields {
    ($fmt:expr) => {{
        let mut s = $fmt.to_string();
        s = s.replace("{Field::ENTRY}", Field::ENTRY);
        s = s.replace("{Field::VERSION}", Field::VERSION);
        s = s.replace("{Field::VLAD}", Field::VLAD);
        s = s.replace("{Field::PREV}", Field::PREV);
        s = s.replace("{Field::LIPMAA}", Field::LIPMAA);
        s = s.replace("{Field::SEQNO}", Field::SEQNO);
        s = s.replace("{Field::OPS}", Field::OPS);
        s = s.replace("{Field::UNLOCK}", Field::UNLOCK);
        s = s.replace("{Field::PROOF}", Field::PROOF);
        s
    }};
    ($fmt:expr, $($args:tt)*) => {{
        let formatted = format!($fmt, $($args)*);
        format_with_fields!(formatted)
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_paths() {
        assert_eq!(Field::Entry.as_str(), Field::ENTRY);
        assert_eq!(Field::Version.as_str(), Field::VERSION);
        assert_eq!(Field::Vlad.as_str(), Field::VLAD);
        assert_eq!(Field::Prev.as_str(), Field::PREV);
        assert_eq!(Field::Lipmaa.as_str(), Field::LIPMAA);
        assert_eq!(Field::Seqno.as_str(), Field::SEQNO);
        assert_eq!(Field::Ops.as_str(), Field::OPS);
        assert_eq!(Field::Unlock.as_str(), Field::UNLOCK);
        assert_eq!(Field::Proof.as_str(), Field::PROOF);
    }
}
