// SPDX-License-Idnetifier: Apache-2.0
use crate::{
    error::{AttributesError, ConversionsError},
    AttrId, AttrView, ConvView, DataView, Error, Multisig, Views,
};
use multicodec::Codec;

pub(crate) struct View<'a> {
    ms: &'a Multisig,
}

impl<'a> TryFrom<&'a Multisig> for View<'a> {
    type Error = Error;

    fn try_from(ms: &'a Multisig) -> Result<Self, Self::Error> {
        Ok(Self { ms })
    }
}

impl AttrView for View<'_> {
    /// for EdDSA Multisigs, the payload encoding is stored using the
    /// AttrId::PayloadEncoding attribute id.
    fn payload_encoding(&self) -> Result<Codec, Error> {
        let v = self
            .ms
            .attributes
            .get(&AttrId::PayloadEncoding)
            .ok_or(AttributesError::MissingPayloadEncoding)?;
        let encoding = Codec::try_from(v.as_slice())?;
        Ok(encoding)
    }
    /// EdDSA signatures only have one scheme so this is meaningless
    fn scheme(&self) -> Result<u8, Error> {
        Ok(0)
    }
}

impl DataView for View<'_> {
    /// For EdDSA Multisig values, the sig data is stored using the
    /// AttrId::SigData attribute id.
    fn sig_bytes(&self) -> Result<Vec<u8>, Error> {
        let sig = self
            .ms
            .attributes
            .get(&AttrId::SigData)
            .ok_or(AttributesError::MissingSignature)?;
        Ok(sig.clone())
    }
}

impl ConvView for View<'_> {
    /// convert to SSH signature format
    fn to_ssh_signature(&self) -> Result<ssh_key::Signature, Error> {
        // get the signature data
        let dv = self.ms.data_view()?;
        let sig_bytes = dv.sig_bytes()?;
        Ok(
            ssh_key::Signature::new(ssh_key::Algorithm::Ed25519, sig_bytes)
                .map_err(|e| ConversionsError::Ssh(e.into()))?,
        )
    }
}
