// SPDX-License-Idnetifier: Apache-2.0
use crate::{Error, Multisig};
use multicodec::Codec;

/// BLS12 381 G1/G2 signature implementation
pub mod bls12381;
/// Edwards curve 25519 signature implementation
pub mod ed25519;
/// Koblitz 256k1 curve implmentation (a.k.a. the Bitcoin curve)
pub mod secp256k1;

// Attributes views let you inquire about the Multisig and retrieve data
// associated with the particular view.

/// trait for returning the attributes of the Multisig
pub trait AttrView {
    /// get the codec that the signed message was encoded with
    fn payload_encoding(&self) -> Result<Codec, Error>;
    /// get the signing scheme identifier if any
    fn scheme(&self) -> Result<u8, Error>;
}

/// trait for returning the data from a Multisig
pub trait DataView {
    /// get the signature bytes from the Multisig
    fn sig_bytes(&self) -> Result<Vec<u8>, Error>;
}

/// trait for converting Multisigs to other formats
pub trait ConvView {
    /// convert the Multisig to an SSH signature
    fn to_ssh_signature(&self) -> Result<ssh_key::Signature, Error>;
}

/// trait for getting threshold attributes
pub trait ThresholdAttrView {
    /// get the threshold value for this multisig share
    fn threshold(&self) -> Result<usize, Error>;
    /// get the limit value for this multisig share
    fn limit(&self) -> Result<usize, Error>;
    /// get the identifier value for this multisig share
    fn identifier(&self) -> Result<u8, Error>;
    /// get the threshold data associated with the signature
    fn threshold_data(&self) -> Result<&[u8], Error>;
}

/// trait for accumulating shares to rebuild a threshold signature
pub trait ThresholdView {
    /// get the signature shares from this multisig
    fn shares(&self) -> Result<Vec<Multisig>, Error>;
    /// add a new share and return the Multisig with the share added
    fn add_share(&self, share: &Multisig) -> Result<Multisig, Error>;
    /// reconstruct the signature from the shares
    fn combine(&self) -> Result<Multisig, Error>;
}

/// trait for getting the other views
pub trait Views {
    /// Provide a read-only view to access the signature attributes
    fn attr_view<'a>(&'a self) -> Result<Box<dyn AttrView + 'a>, Error>;
    /// Provide a read-only view to access signature data
    fn data_view<'a>(&'a self) -> Result<Box<dyn DataView + 'a>, Error>;
    /// Provide a view for converting to other signature formats
    fn conv_view<'a>(&'a self) -> Result<Box<dyn ConvView + 'a>, Error>;
    /// Provide a read-only view to access the threshold signature attributes
    fn threshold_attr_view<'a>(&'a self) -> Result<Box<dyn ThresholdAttrView + 'a>, Error>;
    /// Provide the view for adding a share to a multisig
    fn threshold_view<'a>(&'a self) -> Result<Box<dyn ThresholdView + 'a>, Error>;
}
