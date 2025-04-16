// SPDX-License-Identifier: FSL-1.1
use std::fmt;

/// The values that can be pushed onto the stack
#[derive(Clone, PartialEq)]
pub enum Value {
    /// A binary blob value with debugging hint
    Bin {
        /// Arbitrary description of the data for debugging purposes
        hint: String,
        /// Binary value data
        data: Vec<u8>
    },
    /// A printable string value with debugging hint
    Str {
        /// Arbitrary description of the data for debugging purposes
        hint: String,
        /// String value data
        data: String
    },
    /// Sucess marker
    Success(usize),
    /// Failure marker
    Failure(String),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Value::Bin { hint, data } => write!(f, "Bin(\"{}\": {} bytes)", hint, data.len()),
            Value::Str { hint, data } => write!(f, "Str(\"{}\": {} bytes)", hint, data.len()),
            Value::Success(n) => write!(f, "Success({})", n),
            Value::Failure(e) => write!(f, "Failure(\"{}\")", e),
        }
    }
}

impl From<&[u8]> for Value 
{
    fn from(b: &[u8]) -> Self {
        Value::from(b.to_vec())
    }
}

impl From<Vec<u8>> for Value 
{
    fn from(b: Vec<u8>) -> Self {
        Value::Bin {
            hint: "".to_string(),
            data: b
        }
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::from(s.to_string())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Str { 
            hint: "".to_string(),
            data: s
        }
    }
}

impl From<usize> for Value {
    fn from(n: usize) -> Self {
        Value::Success(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_value() {
        let v: Value = "foo".into();
        assert_eq!(
            Value::Str {
                hint: "".to_string(),
                data: "foo".to_string()
            }, 
            v
        );
    }

    #[test]
    fn test_number_value() {
        let v: Value = 1.into();
        assert_eq!(Value::Success(1), v);
    }
}
