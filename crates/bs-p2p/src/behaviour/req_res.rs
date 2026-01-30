//! Request response types
use std::ops::Deref;

use serde::{Deserialize, Serialize};

/// Simple file exchange protocol
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRequest(Vec<u8>);

impl PeerRequest {
    /// Create a new PeerRequest from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Deref for PeerRequest {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Jeeves Response Bytes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerResponse(Vec<u8>);

impl PeerResponse {
    pub(crate) fn new(file: Vec<u8>) -> Self {
        Self(file)
    }
}

impl Deref for PeerResponse {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
