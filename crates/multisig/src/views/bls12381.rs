// SPDX-License-Idnetifier: Apache-2.0
use crate::{
    error::{AttributesError, ConversionsError, SharesError},
    AttrId, AttrView, Builder, ConvView, DataView, Error, Multisig, ThresholdAttrView,
    ThresholdView, Views,
};
use blsful::{
    vsss_rs::Share, Bls12381G1Impl, Bls12381G2Impl, Signature, SignatureSchemes, SignatureShare,
};
use multicodec::Codec;
use multitrait::{EncodeInto, TryDecodeFrom};
use multiutil::{Varbytes, Varuint};
use std::{collections::BTreeMap, fmt};

/// the name used to identify these signatures in non-Multikey formats
pub const ALGORITHM_NAME_G1: &str = "bls12_381-g1@multisig";
/// the name used to identify these signatures in non-Multikey formats
pub const ALGORITHM_NAME_G1_SHARE: &str = "bls12_381-g1-share@multisig";
/// the name used to identify these signatures in non-Multikey formats
pub const ALGORITHM_NAME_G2: &str = "bls12_381-g2@multisig";
/// the name used to identify these signatures in non-Multikey formats
pub const ALGORITHM_NAME_G2_SHARE: &str = "bls12_381-g2-share@multisig";

/// The different signature scheme methods offered in the blsful BLS crate
#[repr(u8)]
#[derive(Clone, Copy, Default, Hash, Ord, PartialOrd, PartialEq, Eq)]
pub enum SchemeTypeId {
    /// Basic
    Basic,
    /// Message Augmentation
    MessageAugmentation,
    /// ProofOfPossession
    #[default]
    ProofOfPossession,
}

impl SchemeTypeId {
    /// Get the code for the attribute id
    pub fn code(&self) -> u8 {
        (*self).into()
    }

    /// Convert the attribute id to &str
    pub fn as_str(&self) -> &str {
        match self {
            Self::Basic => "basic",
            Self::MessageAugmentation => "message-augmentation",
            Self::ProofOfPossession => "proof-of-possession",
        }
    }
}

impl From<SchemeTypeId> for u8 {
    fn from(val: SchemeTypeId) -> Self {
        val as u8
    }
}

impl TryFrom<u8> for SchemeTypeId {
    type Error = Error;

    fn try_from(c: u8) -> Result<Self, Self::Error> {
        match c {
            0 => Ok(Self::Basic),
            1 => Ok(Self::MessageAugmentation),
            2 => Ok(Self::ProofOfPossession),
            _ => Err(SharesError::InvalidSchemeTypeId(c).into()),
        }
    }
}

impl From<SchemeTypeId> for SignatureSchemes {
    fn from(val: SchemeTypeId) -> Self {
        match val {
            SchemeTypeId::Basic => SignatureSchemes::Basic,
            SchemeTypeId::MessageAugmentation => SignatureSchemes::MessageAugmentation,
            SchemeTypeId::ProofOfPossession => SignatureSchemes::ProofOfPossession,
        }
    }
}

impl From<&SignatureSchemes> for SchemeTypeId {
    fn from(s: &SignatureSchemes) -> Self {
        match s {
            SignatureSchemes::Basic => SchemeTypeId::Basic,
            SignatureSchemes::MessageAugmentation => SchemeTypeId::MessageAugmentation,
            SignatureSchemes::ProofOfPossession => SchemeTypeId::ProofOfPossession,
        }
    }
}

impl<C> From<&Signature<C>> for SchemeTypeId
where
    C: blsful::BlsSignatureImpl,
{
    fn from(s: &Signature<C>) -> Self {
        match s {
            Signature::Basic(_) => SchemeTypeId::Basic,
            Signature::MessageAugmentation(_) => SchemeTypeId::MessageAugmentation,
            Signature::ProofOfPossession(_) => SchemeTypeId::ProofOfPossession,
        }
    }
}

impl<C> From<&SignatureShare<C>> for SchemeTypeId
where
    C: blsful::BlsSignatureImpl,
{
    fn from(s: &SignatureShare<C>) -> Self {
        match s {
            SignatureShare::Basic(_) => SchemeTypeId::Basic,
            SignatureShare::MessageAugmentation(_) => SchemeTypeId::MessageAugmentation,
            SignatureShare::ProofOfPossession(_) => SchemeTypeId::ProofOfPossession,
        }
    }
}

impl From<SchemeTypeId> for Vec<u8> {
    fn from(val: SchemeTypeId) -> Self {
        val.code().encode_into()
    }
}

impl<'a> TryFrom<&'a [u8]> for SchemeTypeId {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (id, _) = Self::try_decode_from(bytes)?;
        Ok(id)
    }
}

impl<'a> TryDecodeFrom<'a> for SchemeTypeId {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (code, ptr) = u8::try_decode_from(bytes)?;
        Ok((Self::try_from(code)?, ptr))
    }
}

impl TryFrom<&str> for SchemeTypeId {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_ascii_lowercase().as_str() {
            "basic" => Ok(Self::Basic),
            "message-augmentation" => Ok(Self::MessageAugmentation),
            "proof-of-possession" => Ok(Self::ProofOfPossession),
            _ => Err(SharesError::InvalidShareTypeName(s.to_string()).into()),
        }
    }
}

impl fmt::Display for SchemeTypeId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// tuple of combined signature data
#[derive(Clone)]
pub struct SigCombined(
    /// signature scheme
    pub SchemeTypeId,
    /// signature bytes
    pub Vec<u8>,
);

impl From<SigCombined> for Vec<u8> {
    fn from(val: SigCombined) -> Self {
        let mut v = Vec::default();
        // add in the signature type id
        v.append(&mut val.0.into());
        // add in the signature bytes
        v.append(&mut Varbytes(val.1.clone()).into());
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for SigCombined {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (sig, _) = Self::try_decode_from(bytes)?;
        Ok(sig)
    }
}

impl<'a> TryDecodeFrom<'a> for SigCombined {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // try to decode the signature type
        let (sig_type, ptr) = SchemeTypeId::try_decode_from(bytes)?;
        // try to decode the signature bytes
        let (sig_data, ptr) = Varbytes::try_decode_from(ptr)?;
        Ok((Self(sig_type, sig_data.to_inner()), ptr))
    }
}

/// tuple of signature share data with threshold attributes
#[derive(Clone)]
pub struct SigShare(
    /// identifier
    pub u8,
    /// threshold
    pub usize,
    /// limit
    pub usize,
    /// signature scheme
    pub SchemeTypeId,
    /// share bytes
    pub Vec<u8>,
);

impl From<SigShare> for Vec<u8> {
    fn from(val: SigShare) -> Self {
        let mut v = Vec::default();
        // add in the share identifier
        v.append(&mut Varuint(val.0).into());
        // add in the share threshold
        v.append(&mut Varuint(val.1).into());
        // add in the share limit
        v.append(&mut Varuint(val.2).into());
        // add in the share type id
        v.append(&mut val.3.into());
        // add in the share data
        v.append(&mut Varbytes(val.4.clone()).into());
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for SigShare {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (share, _) = Self::try_decode_from(bytes)?;
        Ok(share)
    }
}

impl<'a> TryDecodeFrom<'a> for SigShare {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // try to decode the identifier
        let (id, ptr) = Varuint::<u8>::try_decode_from(bytes)?;
        // try to decode the threshold
        let (threshold, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        // try to decode the limit
        let (limit, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        // try to decode the share type id
        let (share_type, ptr) = SchemeTypeId::try_decode_from(ptr)?;
        // try to decode the share data
        let (share_data, ptr) = Varbytes::try_decode_from(ptr)?;
        Ok((
            Self(
                id.to_inner(),
                threshold.to_inner(),
                limit.to_inner(),
                share_type,
                share_data.to_inner(),
            ),
            ptr,
        ))
    }
}

#[derive(Clone, Default)]
pub(crate) struct ThresholdData(pub(crate) BTreeMap<u8, SigShare>);

impl From<ThresholdData> for Vec<u8> {
    fn from(val: ThresholdData) -> Self {
        let mut v = Vec::default();
        // add in the number of sig shares
        v.append(&mut Varuint(val.0.len()).into());
        // add in the sig shares
        val.0.iter().for_each(|(_, share)| {
            v.append(&mut share.clone().into());
        });
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for ThresholdData {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (tdata, _) = Self::try_decode_from(bytes)?;
        Ok(tdata)
    }
}

impl<'a> TryDecodeFrom<'a> for ThresholdData {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // try to decode the number of shares
        let (num_shares, ptr) = Varuint::<usize>::try_decode_from(bytes)?;
        // decode the signature-specific attributes
        let (shares, ptr) = match *num_shares {
            0 => (BTreeMap::default(), ptr),
            _ => {
                let mut shares = BTreeMap::new();
                let mut p = ptr;
                for _ in 0..*num_shares {
                    let (share, ptr) = SigShare::try_decode_from(p)?;
                    shares.insert(share.0, share);
                    p = ptr;
                }
                (shares, p)
            }
        };

        Ok((Self(shares), ptr))
    }
}

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
    /// for Bls Multisigs, the payload encoding is stored using the
    /// SchemeTypeId::PayloadEncoding attribute id.
    fn payload_encoding(&self) -> Result<Codec, Error> {
        let v = self
            .ms
            .attributes
            .get(&AttrId::PayloadEncoding)
            .ok_or(AttributesError::MissingPayloadEncoding)?;
        let encoding = Codec::try_from(v.as_slice())?;
        Ok(encoding)
    }
    /// Bls signatures have three different schemes which is needed
    /// for verifying the signatures
    fn scheme(&self) -> Result<u8, Error> {
        let v = self
            .ms
            .attributes
            .get(&AttrId::Scheme)
            .ok_or(AttributesError::MissingScheme)?;
        let scheme = Varuint::<u8>::try_from(v.as_slice())?;
        Ok(*scheme)
    }
}

impl DataView for View<'_> {
    /// For Bls Multisig values, the sig data is stored using the
    /// SchemeTypeId::SigData attribute id.
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

        // get the scheme
        let av = self.ms.attr_view()?;
        let scheme_type = SchemeTypeId::try_from(av.scheme()?)?;

        match self.ms.codec {
            Codec::Bls12381G1Msig => {
                // create the combined sig tuple
                let sig_data: Vec<u8> = SigCombined(scheme_type, sig_bytes).into();

                Ok(ssh_key::Signature::new(
                    ssh_key::Algorithm::Other(
                        ssh_key::AlgorithmName::new(ALGORITHM_NAME_G1)
                            .map_err(|e| ConversionsError::Ssh(e.into()))?,
                    ),
                    sig_data,
                )
                .map_err(|e| ConversionsError::Ssh(e.into()))?)
            }
            Codec::Bls12381G2Msig => {
                // create the combined sig tuple
                let sig_data: Vec<u8> = SigCombined(scheme_type, sig_bytes).into();

                Ok(ssh_key::Signature::new(
                    ssh_key::Algorithm::Other(
                        ssh_key::AlgorithmName::new(ALGORITHM_NAME_G2)
                            .map_err(|e| ConversionsError::Ssh(e.into()))?,
                    ),
                    sig_data,
                )
                .map_err(|e| ConversionsError::Ssh(e.into()))?)
            }
            Codec::Bls12381G1ShareMsig => {
                // get the threshold attributes
                let av = self.ms.threshold_attr_view()?;
                let threshold = av.threshold()?;
                let limit = av.limit()?;
                let identifier = av.identifier()?;

                // create the sig share tuple
                let sig_data: Vec<u8> =
                    SigShare(identifier, threshold, limit, scheme_type, sig_bytes).into();

                Ok(ssh_key::Signature::new(
                    ssh_key::Algorithm::Other(
                        ssh_key::AlgorithmName::new(ALGORITHM_NAME_G1_SHARE)
                            .map_err(|e| ConversionsError::Ssh(e.into()))?,
                    ),
                    sig_data,
                )
                .map_err(|e| ConversionsError::Ssh(e.into()))?)
            }
            Codec::Bls12381G2ShareMsig => {
                // get the threshold attributes
                let av = self.ms.threshold_attr_view()?;
                let threshold = av.threshold()?;
                let limit = av.limit()?;
                let identifier = av.identifier()?;

                // create the sig share tuple
                let sig_data: Vec<u8> =
                    SigShare(identifier, threshold, limit, scheme_type, sig_bytes).into();

                Ok(ssh_key::Signature::new(
                    ssh_key::Algorithm::Other(
                        ssh_key::AlgorithmName::new(ALGORITHM_NAME_G2_SHARE)
                            .map_err(|e| ConversionsError::Ssh(e.into()))?,
                    ),
                    sig_data,
                )
                .map_err(|e| ConversionsError::Ssh(e.into()))?)
            }
            _ => Err(Error::UnsupportedAlgorithm(self.ms.codec.to_string())),
        }
    }
}

impl ThresholdAttrView for View<'_> {
    /// get the threshold value for this multisig
    fn threshold(&self) -> Result<usize, Error> {
        let threshold = self
            .ms
            .attributes
            .get(&AttrId::Threshold)
            .ok_or(AttributesError::MissingThreshold)?;
        Ok(Varuint::<usize>::try_from(threshold.as_slice())?.to_inner())
    }
    /// get the limit value for this multisig
    fn limit(&self) -> Result<usize, Error> {
        let limit = self
            .ms
            .attributes
            .get(&AttrId::Limit)
            .ok_or(AttributesError::MissingLimit)?;
        Ok(Varuint::<usize>::try_from(limit.as_slice())?.to_inner())
    }
    /// get the share identifier
    fn identifier(&self) -> Result<u8, Error> {
        match self.ms.codec {
            Codec::Bls12381G1ShareMsig | Codec::Bls12381G2ShareMsig => {
                let identifier = self
                    .ms
                    .attributes
                    .get(&AttrId::ShareIdentifier)
                    .ok_or(AttributesError::MissingIdentifier)?;
                Ok(Varuint::<u8>::try_from(identifier.as_slice())?.to_inner())
            }
            _ => Err(SharesError::NotASignatureShare.into()),
        }
    }
    /// get the threshold data
    fn threshold_data(&self) -> Result<&[u8], Error> {
        let v = self
            .ms
            .attributes
            .get(&AttrId::ThresholdData)
            .ok_or(AttributesError::MissingThresholdData)?;
        Ok(v.as_slice())
    }
}

/// trait for accumulating shares to rebuild a threshold signature
impl ThresholdView for View<'_> {
    /// get the signature shares
    fn shares(&self) -> Result<Vec<Multisig>, Error> {
        // get the codec for the new share multisigs
        let codec = match self.ms.codec {
            Codec::Bls12381G1Msig => Codec::Bls12381G1ShareMsig,
            Codec::Bls12381G2Msig => Codec::Bls12381G2ShareMsig,
            Codec::Bls12381G1ShareMsig | Codec::Bls12381G2ShareMsig => {
                return Err(SharesError::IsASignatureShare.into())
            }
            _ => return Err(Error::UnsupportedAlgorithm(self.ms.codec.to_string())),
        };

        // current Multisig threshold data
        let threshold_data = {
            let av = self.ms.threshold_attr_view()?;
            match av.threshold_data() {
                Ok(b) => ThresholdData::try_from(b).unwrap_or_default(),
                Err(_) => ThresholdData::default(),
            }
        };

        // build the vec for the shares
        let mut shares = Vec::with_capacity(threshold_data.0.len());

        // build multisigs out of each share
        threshold_data
            .0
            .values()
            .try_for_each(|share| -> Result<(), Error> {
                let encoding = {
                    let av = self.ms.attr_view()?;
                    av.payload_encoding()?
                };
                // build a multisig share out of the share, preserve the message
                // and the payload encoding value
                let share = Builder::new(codec)
                    .with_message_bytes(&self.ms.message.as_slice())
                    .with_identifier(share.0)
                    .with_threshold(share.1)
                    .with_limit(share.2)
                    .with_signature_bytes(&share.4)
                    .with_payload_encoding(encoding)
                    .with_scheme(share.3.into())
                    .try_build()?;
                // add it to the list of shares
                shares.push(share);
                Ok(())
            })?;

        Ok(shares)
    }
    /// add a new share and return the Multisig with the share added
    fn add_share(&self, share: &Multisig) -> Result<Multisig, Error> {
        // check the codec is correct for this function
        match self.ms.codec {
            Codec::Bls12381G1Msig | Codec::Bls12381G2Msig => {}
            Codec::Bls12381G1ShareMsig | Codec::Bls12381G2ShareMsig => {
                return Err(SharesError::IsASignatureShare.into())
            }
            _ => return Err(Error::UnsupportedAlgorithm(self.ms.codec.to_string())),
        };

        let (sdata, identifier, threshold, limit, encoding) = {
            // get the scheme
            let av = share.attr_view()?;
            let scheme_type = SchemeTypeId::try_from(av.scheme()?)?;
            // get the share's attributes
            let av = share.threshold_attr_view()?;
            let threshold = av.threshold()?;
            let limit = av.limit()?;
            let identifier = av.identifier()?;

            // get the share's signature data
            let dv = share.data_view()?;
            let sig_bytes = dv.sig_bytes()?;

            let encoding = {
                let av = self.ms.attr_view()?;
                av.payload_encoding().ok()
            };

            // create the sig share tuple
            (
                SigShare(identifier, threshold, limit, scheme_type, sig_bytes),
                identifier,
                threshold,
                limit,
                encoding,
            )
        };

        // update the threshold data
        let threshold_data: Vec<u8> = {
            let av = self.ms.threshold_attr_view()?;
            let mut tdata = match av.threshold_data() {
                Ok(b) => ThresholdData::try_from(b).unwrap_or_default(),
                Err(_) => ThresholdData::default(),
            };
            // insert the share data into the list of shares
            tdata.0.insert(identifier, sdata);
            tdata.into()
        };

        // get the payload encoding
        let encoding = {
            let av = self.ms.attr_view()?;
            // if this multisig doesn't have payload encoding set, set it to
            // the value from the first share added
            match av.payload_encoding() {
                Ok(encoding) => Some(encoding),
                Err(_) => encoding,
            }
        };

        // if this multisig doesn't already have the threshold/limit set then
        // set it to match the values from the first share added
        let av = share.threshold_attr_view()?;
        let threshold = av.threshold().unwrap_or(threshold);
        let limit = av.limit().unwrap_or(limit);

        let builder = Builder::new(self.ms.codec)
            .with_message_bytes(&self.ms.message.as_slice())
            .with_threshold(threshold)
            .with_limit(limit)
            .with_threshold_data(&threshold_data);

        if let Some(encoding) = encoding {
            builder.with_payload_encoding(encoding).try_build()
        } else {
            builder.try_build()
        }
    }
    /// reconstruct the signature from the shares
    fn combine(&self) -> Result<Multisig, Error> {
        // current Multisig threshold data
        let threshold_data = {
            let av = self.ms.threshold_attr_view()?;
            match av.threshold_data() {
                Ok(b) => ThresholdData::try_from(b).unwrap_or_default(),
                Err(_) => ThresholdData::default(),
            }
        };

        // check that we have enough shares to combine
        let num_shares = threshold_data.0.len();
        let av = self.ms.threshold_attr_view()?;
        if num_shares < av.threshold()? {
            return Err(SharesError::NotEnoughShares.into());
        }

        match self.ms.codec {
            Codec::Bls12381G1Msig => {
                let mut share_type_id: Option<SchemeTypeId> = None;
                let mut shares = Vec::default();
                threshold_data
                    .0
                    .iter()
                    .try_for_each(|(id, share)| -> Result<(), Error> {
                        let vsss = Share::with_identifier_and_value(*id, share.4.as_slice());
                        // check to make sure all of the shares are of the same type
                        if let Some(sti) = share_type_id {
                            if sti != share.3 {
                                return Err(SharesError::ShareTypeMismatch.into());
                            }
                        } else {
                            share_type_id = Some(share.3);
                        }
                        let s = match share.3 {
                            SchemeTypeId::Basic => SignatureShare::<Bls12381G1Impl>::Basic(vsss),
                            SchemeTypeId::MessageAugmentation => {
                                SignatureShare::<Bls12381G1Impl>::MessageAugmentation(vsss)
                            }
                            SchemeTypeId::ProofOfPossession => {
                                SignatureShare::<Bls12381G1Impl>::ProofOfPossession(vsss)
                            }
                        };
                        shares.push(s);
                        Ok(())
                    })?;

                let sig = Signature::from_shares(shares.as_slice())
                    .map_err(|e| SharesError::ShareCombineFailed(e.to_string()))?;
                let encoding = {
                    let av = self.ms.attr_view()?;
                    av.payload_encoding()?
                };
                Builder::new_from_bls_signature(&sig)?
                    .with_message_bytes(&self.ms.message.as_slice())
                    .with_payload_encoding(encoding)
                    .try_build()
            }
            Codec::Bls12381G2Msig => {
                let mut share_type_id: Option<SchemeTypeId> = None;
                let mut shares = Vec::default();
                threshold_data
                    .0
                    .iter()
                    .try_for_each(|(id, share)| -> Result<(), Error> {
                        let vsss = Share::with_identifier_and_value(*id, share.4.as_slice());
                        // check to make sure all of the shares are of the same type
                        if let Some(sti) = share_type_id {
                            if sti != share.3 {
                                return Err(SharesError::ShareTypeMismatch.into());
                            }
                        } else {
                            share_type_id = Some(share.3);
                        }
                        let s = match share.3 {
                            SchemeTypeId::Basic => SignatureShare::<Bls12381G2Impl>::Basic(vsss),
                            SchemeTypeId::MessageAugmentation => {
                                SignatureShare::<Bls12381G2Impl>::MessageAugmentation(vsss)
                            }
                            SchemeTypeId::ProofOfPossession => {
                                SignatureShare::<Bls12381G2Impl>::ProofOfPossession(vsss)
                            }
                        };
                        shares.push(s);
                        Ok(())
                    })?;

                let sig = Signature::from_shares(shares.as_slice())
                    .map_err(|e| SharesError::ShareCombineFailed(e.to_string()))?;
                let encoding = {
                    let av = self.ms.attr_view()?;
                    av.payload_encoding().ok()
                };
                let builder = Builder::new_from_bls_signature(&sig)?
                    .with_message_bytes(&self.ms.message.as_slice());

                if let Some(encoding) = encoding {
                    builder.with_payload_encoding(encoding).try_build()
                } else {
                    builder.try_build()
                }
            }
            _ => Err(Error::UnsupportedAlgorithm(self.ms.codec.to_string())),
        }
    }
}
