// SPDX-License-Idnetifier: Apache-2.0
/// Errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A multicodec decoding error
    #[error(transparent)]
    Multicodec(#[from] multicodec::Error),
    /// Multiutil error
    #[error(transparent)]
    Multiutil(#[from] multiutil::Error),
    /// Missing hash data
    #[error("Missing hash data")]
    MissingHash,
    /// Error with the hash scheme
    #[error("Unsupported hash algorithm: {0}")]
    UnsupportedHash(multicodec::Codec),
}
