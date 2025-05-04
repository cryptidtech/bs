/// The values that can be pushed onto the stack
#[derive(Clone, PartialEq, Debug)]
pub enum Value {
    /// A binary blob value with debugging hint
    Bin {
        /// Arbitrary description of the data for debugging purposes
        hint: String,
        /// Binary value data
        data: Vec<u8>,
    },
    /// A printable string value with debugging hint
    Str {
        /// Arbitrary description of the data for debugging purposes
        hint: String,
        /// String value data
        data: String,
    },
    /// Sucess marker
    Success(usize),
    /// Failure marker
    Failure(String),
}

impl From<&[u8]> for Value {
    fn from(b: &[u8]) -> Self {
        Value::from(b.to_vec())
    }
}

impl From<Vec<u8>> for Value {
    fn from(b: Vec<u8>) -> Self {
        Value::Bin {
            hint: "".to_string(),
            data: b,
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
            data: s,
        }
    }
}

impl From<usize> for Value {
    fn from(n: usize) -> Self {
        Value::Success(n)
    }
}
