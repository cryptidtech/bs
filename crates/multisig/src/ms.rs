// SPDX-License-Idnetifier: Apache-2.0
use crate::{
    error::AttributesError,
    views::{
        bls12381::{self, SchemeTypeId},
        ed25519, secp256k1,
    },
    AttrId, AttrView, ConvView, DataView, Error, ThresholdAttrView, ThresholdView, Views,
};
use blsful::{inner_types::GroupEncoding, vsss_rs::Share, Signature, SignatureShare};
use multibase::Base;
use multicodec::Codec;
use multitrait::{Null, TryDecodeFrom};
use multiutil::{BaseEncoded, CodecInfo, EncodingInfo, Varbytes, Varuint};
use std::{collections::BTreeMap, fmt};

/// the list of signature codecs currently supported
pub const SIG_CODECS: [Codec; 4] = [
    Codec::Bls12381G1Msig,
    Codec::Bls12381G2Msig,
    Codec::EddsaMsig,
    // Codec::Es256Msig,
    // Codec::Es384Msig,
    // Codec::Es521Msig,
    // Codec::Rs256Msig,
    Codec::Es256KMsig, //,
                       //Codec::LamportMsig,
];

/// the list of signature share codecs supported
pub const SIG_SHARE_CODECS: [Codec; 2] = [
    Codec::Bls12381G1ShareMsig,
    Codec::Bls12381G2ShareMsig, //,
                                //Codec::LamportShareMsig,
];

/// the multisig sigil
pub const SIGIL: Codec = Codec::Multisig;

/// a base encoded varsig
pub type EncodedMultisig = BaseEncoded<Multisig>;

/// The multisig attributes type
pub type Attributes = BTreeMap<AttrId, Vec<u8>>;

/// The multisig structure
#[derive(Clone, Default, PartialEq)]
pub struct Multisig {
    /// signature codec
    pub(crate) codec: Codec,
    /// the message part of a combined signature
    pub message: Vec<u8>,
    /// signature specific attributes
    pub attributes: Attributes,
}

impl CodecInfo for Multisig {
    /// Return that we are a Multisig object
    fn preferred_codec() -> Codec {
        SIGIL
    }

    /// Return the signing codec for the Multisig
    fn codec(&self) -> Codec {
        self.codec
    }
}

impl EncodingInfo for Multisig {
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    /// return the payload encoding
    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl From<Multisig> for Vec<u8> {
    fn from(val: Multisig) -> Self {
        let mut v = Vec::default();
        // add in the sigil
        v.append(&mut SIGIL.into());
        // add in the signature codec
        v.append(&mut val.codec.into());
        // add in the message
        v.append(&mut Varbytes(val.message.clone()).into());
        // add in the number of attributes
        v.append(&mut Varuint(val.attributes.len()).into());
        // add in the attributes
        val.attributes.iter().for_each(|(id, attr)| {
            v.append(&mut (*id).into());
            v.append(&mut Varbytes(attr.clone()).into());
        });
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for Multisig {
    type Error = Error;

    fn try_from(s: &'a [u8]) -> Result<Self, Self::Error> {
        let (ms, _) = Self::try_decode_from(s)?;
        Ok(ms)
    }
}

impl<'a> TryDecodeFrom<'a> for Multisig {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the sigil
        let (sigil, ptr) = Codec::try_decode_from(bytes)?;
        if sigil != SIGIL {
            return Err(Error::MissingSigil);
        }
        // decode the signature codec
        let (codec, ptr) = Codec::try_decode_from(ptr)?;
        // decode the message
        let (message, ptr) = Varbytes::try_decode_from(ptr)?;
        let message = message.to_inner();
        // decode the number of signature-specific attributes
        let (num_attr, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        // decode the signature-specific attributes
        let (attributes, ptr) = match *num_attr {
            0 => (Attributes::default(), ptr),
            _ => {
                let mut attributes = Attributes::new();
                let mut p = ptr;
                for _ in 0..*num_attr {
                    let (id, ptr) = AttrId::try_decode_from(p)?;
                    let (attr, ptr) = Varbytes::try_decode_from(ptr)?;
                    if attributes.insert(id, (*attr).clone()).is_some() {
                        return Err(Error::DuplicateAttribute(id.code()));
                    }
                    p = ptr;
                }
                (attributes, p)
            }
        };
        Ok((
            Self {
                codec,
                message,
                attributes,
            },
            ptr,
        ))
    }
}

impl Null for Multisig {
    fn null() -> Self {
        Self::default()
    }

    fn is_null(&self) -> bool {
        *self == Self::null()
    }
}

impl fmt::Debug for Multisig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} - {:?} - {}",
            SIGIL,
            self.codec(),
            if !self.message.is_empty() {
                "Combined"
            } else {
                "Detached"
            },
        )
    }
}

impl Views for Multisig {
    /// Provide a read-only view to access the signature attributes
    fn attr_view<'a>(&'a self) -> Result<Box<dyn AttrView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1Msig
            | Codec::Bls12381G2Msig
            | Codec::Bls12381G1ShareMsig
            | Codec::Bls12381G2ShareMsig => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::EddsaMsig => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Es256KMsig => Ok(Box::new(secp256k1::View::try_from(self)?)),
            _ => Err(AttributesError::UnsupportedCodec(self.codec).into()),
        }
    }
    /// Provide a read-only view to access signature data
    fn data_view<'a>(&'a self) -> Result<Box<dyn DataView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1Msig
            | Codec::Bls12381G2Msig
            | Codec::Bls12381G1ShareMsig
            | Codec::Bls12381G2ShareMsig => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::EddsaMsig => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Es256KMsig => Ok(Box::new(secp256k1::View::try_from(self)?)),
            _ => Err(AttributesError::UnsupportedCodec(self.codec).into()),
        }
    }
    /// Provide a read-only view to access signature data
    fn conv_view<'a>(&'a self) -> Result<Box<dyn ConvView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1Msig
            | Codec::Bls12381G2Msig
            | Codec::Bls12381G1ShareMsig
            | Codec::Bls12381G2ShareMsig => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::EddsaMsig => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Es256KMsig => Ok(Box::new(secp256k1::View::try_from(self)?)),
            _ => Err(AttributesError::UnsupportedCodec(self.codec).into()),
        }
    }
    /// Provide a read-only view to access the threshold signature attributes
    fn threshold_attr_view<'a>(&'a self) -> Result<Box<dyn ThresholdAttrView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1Msig
            | Codec::Bls12381G2Msig
            | Codec::Bls12381G1ShareMsig
            | Codec::Bls12381G2ShareMsig => Ok(Box::new(bls12381::View::try_from(self)?)),
            _ => Err(AttributesError::UnsupportedCodec(self.codec).into()),
        }
    }
    /// Provide the view for adding a share to a multisig
    fn threshold_view<'a>(&'a self) -> Result<Box<dyn ThresholdView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1Msig | Codec::Bls12381G2Msig => {
                Ok(Box::new(bls12381::View::try_from(self)?))
            }
            _ => Err(AttributesError::UnsupportedCodec(self.codec).into()),
        }
    }
}

/// Builder for Multisigs
#[derive(Clone, Default)]
pub struct Builder {
    codec: Codec,
    message: Option<Vec<u8>>,
    base_encoding: Option<Base>,
    attributes: Option<BTreeMap<AttrId, Vec<u8>>>,
    shares: Option<Vec<Multisig>>,
}

impl Builder {
    /// create a new Multisig
    pub fn new(codec: Codec) -> Self {
        Self {
            codec,
            ..Default::default()
        }
    }

    /// create new multisig from ssh Signature
    pub fn new_from_ssh_signature(sig: &ssh_key::Signature) -> Result<Self, Error> {
        let mut attributes = BTreeMap::new();
        use ssh_key::Algorithm::*;
        match sig.algorithm() {
            Ed25519 => {
                attributes.insert(AttrId::SigData, sig.as_bytes().to_vec());
                Ok(Self {
                    codec: Codec::EddsaMsig,
                    attributes: Some(attributes),
                    ..Default::default()
                })
            }
            Other(name) => match name.as_str() {
                secp256k1::ALGORITHM_NAME => {
                    attributes.insert(AttrId::SigData, sig.as_bytes().to_vec());
                    Ok(Self {
                        codec: Codec::Es256KMsig,
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G1 => {
                    let sig_combined = bls12381::SigCombined::try_from(sig.as_bytes())?;
                    attributes.insert(AttrId::Scheme, sig_combined.0.into());
                    attributes.insert(AttrId::SigData, sig_combined.1);
                    Ok(Self {
                        codec: Codec::Bls12381G1Msig,
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G2 => {
                    let sig_combined = bls12381::SigCombined::try_from(sig.as_bytes())?;
                    attributes.insert(AttrId::Scheme, sig_combined.0.into());
                    attributes.insert(AttrId::SigData, sig_combined.1);
                    Ok(Self {
                        codec: Codec::Bls12381G2Msig,
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G1_SHARE => {
                    let sig_share = bls12381::SigShare::try_from(sig.as_bytes())?;
                    attributes.insert(AttrId::ShareIdentifier, Varuint(sig_share.0).into());
                    attributes.insert(AttrId::Threshold, Varuint(sig_share.1).into());
                    attributes.insert(AttrId::Limit, Varuint(sig_share.2).into());
                    attributes.insert(AttrId::Scheme, sig_share.3.into());
                    attributes.insert(AttrId::SigData, sig_share.4);
                    Ok(Self {
                        codec: Codec::Bls12381G1ShareMsig,
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G2_SHARE => {
                    let sig_share = bls12381::SigShare::try_from(sig.as_bytes())?;
                    attributes.insert(AttrId::ShareIdentifier, Varuint(sig_share.0).into());
                    attributes.insert(AttrId::Threshold, Varuint(sig_share.1).into());
                    attributes.insert(AttrId::Limit, Varuint(sig_share.2).into());
                    attributes.insert(AttrId::Scheme, sig_share.3.into());
                    attributes.insert(AttrId::SigData, sig_share.4);
                    Ok(Self {
                        codec: Codec::Bls12381G1ShareMsig,
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                _ => Err(Error::UnsupportedAlgorithm(name.as_str().to_string())),
            },
            _ => Err(Error::UnsupportedAlgorithm(sig.algorithm().to_string())),
        }
    }

    /// create a new builder from a Bls Signature
    pub fn new_from_bls_signature<C>(sig: &Signature<C>) -> Result<Self, Error>
    where
        C: blsful::BlsSignatureImpl,
    {
        let scheme_type_id = SchemeTypeId::from(sig);
        let sig_bytes: Vec<u8> = sig.as_raw_value().to_bytes().as_ref().to_vec();
        println!("signature length: {}", sig_bytes.len());
        let codec = match sig_bytes.len() {
            48 => Codec::Bls12381G1Msig, // G1Projective::to_compressed()
            96 => Codec::Bls12381G2Msig, // G2Projective::to_compressed()
            _ => {
                return Err(Error::UnsupportedAlgorithm(
                    "invalid Bls signature size".to_string(),
                ))
            }
        };
        let mut attributes = BTreeMap::new();
        attributes.insert(AttrId::SigData, sig_bytes);
        attributes.insert(AttrId::Scheme, scheme_type_id.into());
        Ok(Self {
            codec,
            attributes: Some(attributes),
            ..Default::default()
        })
    }

    /// create a new builder from a Bls SignatureShare
    pub fn new_from_bls_signature_share<C>(
        threshold: usize,
        limit: usize,
        sigshare: &SignatureShare<C>,
    ) -> Result<Self, Error>
    where
        C: blsful::BlsSignatureImpl,
    {
        let scheme_type_id = SchemeTypeId::from(sigshare);
        let sigshare = sigshare.as_raw_value();
        let identifier = sigshare.identifier();
        let value = sigshare.value_vec();
        println!("sigshare len: {}", value.len());
        let codec = match value.len() {
            48 => Codec::Bls12381G1ShareMsig, // large pubkeys, small signatures
            96 => Codec::Bls12381G2ShareMsig, // small pubkeys, large signatures
            _ => {
                return Err(Error::UnsupportedAlgorithm(
                    "invalid Bls signature size".to_string(),
                ))
            }
        };
        let mut attributes = BTreeMap::new();
        attributes.insert(AttrId::SigData, value);
        attributes.insert(AttrId::Threshold, Varuint(threshold).into());
        attributes.insert(AttrId::Limit, Varuint(limit).into());
        attributes.insert(AttrId::ShareIdentifier, Varuint(identifier).into());
        attributes.insert(AttrId::Scheme, scheme_type_id.into());
        Ok(Self {
            codec,
            attributes: Some(attributes),
            ..Default::default()
        })
    }

    /// set the base encoding codec
    pub fn with_base_encoding(mut self, base: Base) -> Self {
        self.base_encoding = Some(base);
        self
    }

    /// add a message payload for a combined signature
    pub fn with_message_bytes(mut self, msg: &impl AsRef<[u8]>) -> Self {
        let m: Vec<u8> = msg.as_ref().into();
        self.message = Some(m);
        self
    }

    fn with_attribute(mut self, attr: AttrId, data: &Vec<u8>) -> Self {
        let mut attributes = self.attributes.unwrap_or_default();
        attributes.insert(attr, data.to_owned());
        self.attributes = Some(attributes);
        self
    }

    /// set the payload encoding codec
    pub fn with_payload_encoding(self, codec: Codec) -> Self {
        self.with_attribute(AttrId::PayloadEncoding, &codec.into())
    }

    /// set the signing scheme
    pub fn with_scheme(self, scheme: u8) -> Self {
        self.with_attribute(AttrId::Scheme, &Varuint(scheme).into())
    }

    /// add a signature payload
    pub fn with_signature_bytes(self, data: &impl AsRef<[u8]>) -> Self {
        self.with_attribute(AttrId::SigData, &data.as_ref().to_vec())
    }

    /// add the threshold signature threshold
    pub fn with_threshold(self, threshold: usize) -> Self {
        self.with_attribute(AttrId::Threshold, &Varuint(threshold).into())
    }

    /// add the threshold signature limit
    pub fn with_limit(self, limit: usize) -> Self {
        self.with_attribute(AttrId::Limit, &Varuint(limit).into())
    }

    /// add the threshold signature identifier
    pub fn with_identifier(self, identifier: u8) -> Self {
        self.with_attribute(AttrId::ShareIdentifier, &Varuint(identifier).into())
    }

    /// add the threshold data
    pub fn with_threshold_data(self, tdata: &impl AsRef<[u8]>) -> Self {
        self.with_attribute(AttrId::ThresholdData, &tdata.as_ref().to_vec())
    }

    /// add a signature share
    pub fn add_signature_share(mut self, share: &Multisig) -> Self {
        let mut shares = self.shares.unwrap_or_default();
        shares.push(share.clone());
        self.shares = Some(shares);
        self
    }

    /// build a base encoded varsig
    pub fn try_build_encoded(self) -> Result<EncodedMultisig, Error> {
        Ok(BaseEncoded::new(
            self.base_encoding
                .unwrap_or_else(Multisig::preferred_encoding),
            self.try_build()?,
        ))
    }

    /// try to build it
    pub fn try_build(self) -> Result<Multisig, Error> {
        let codec = self.codec;
        let message = self.message.unwrap_or_default();
        let attributes = self.attributes.unwrap_or_default();
        let mut ms = Multisig {
            codec,
            message,
            attributes,
        };
        if let Some(shares) = self.shares {
            for share in &shares {
                ms = {
                    let tv = ms.threshold_view()?;
                    tv.add_share(share)?
                };
            }
            Ok(ms)
        } else {
            Ok(ms)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoded() {
        for codec in SIG_CODECS {
            let ms = Builder::new(codec)
                .with_signature_bytes(&[0u8; 64])
                .try_build_encoded()
                .unwrap();
            let s = ms.to_string();
            assert_eq!(ms, EncodedMultisig::try_from(s.as_str()).unwrap());
        }
    }

    #[test]
    fn test_default() {
        let ms1 = Builder::new(Codec::default())
            .with_signature_bytes(&Vec::default())
            .try_build_encoded()
            .unwrap();
        let s = ms1.to_string();
        let ms2 = EncodedMultisig::try_from(s.as_str()).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_eddsa() {
        let ms = Builder::new(Codec::EddsaMsig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let v: Vec<u8> = ms.clone().into();
        assert_eq!(ms, Multisig::try_from(v.as_slice()).unwrap());
    }

    #[test]
    fn test_es256k() {
        let ms = Builder::new(Codec::Es256KMsig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let v: Vec<u8> = ms.clone().into();
        assert_eq!(ms, Multisig::try_from(v.as_slice()).unwrap());
    }

    #[test]
    fn test_bls_signature() {
        let sk = blsful::Bls12381G2::new_secret_key();
        let sig = sk
            .sign(
                blsful::SignatureSchemes::ProofOfPossession,
                b"for great justice, move every zig!",
            )
            .unwrap();

        let ms = Builder::new_from_bls_signature(&sig)
            .unwrap()
            .try_build()
            .unwrap();

        let v: Vec<u8> = ms.clone().into();
        assert_eq!(ms, Multisig::try_from(v.as_slice()).unwrap());
    }

    #[test]
    fn test_bls_signature_combine() {
        let sk = blsful::Bls12381G2::new_secret_key();
        let sig = sk
            .sign(
                blsful::SignatureSchemes::ProofOfPossession,
                b"for great justice, move every zig!",
            )
            .unwrap();

        let ms1 = Builder::new_from_bls_signature(&sig)
            .unwrap()
            .try_build()
            .unwrap();

        let sk_shares = sk.split(3, 4).unwrap();

        let mut sigs = Vec::default();
        sk_shares.iter().for_each(|sk| {
            let sig = sk
                .sign(
                    blsful::SignatureSchemes::ProofOfPossession,
                    b"for great justice, move every zig!",
                )
                .unwrap();
            sigs.push(
                Builder::new_from_bls_signature_share(3, 4, &sig)
                    .unwrap()
                    .try_build()
                    .unwrap(),
            );
        });

        // build a new signature from the parts
        let mut builder = Builder::new(Codec::Bls12381G2Msig);
        for sig in &sigs {
            builder = builder.add_signature_share(sig);
        }
        let ms2 = builder.try_build().unwrap();

        let av = ms2.threshold_attr_view().unwrap();
        assert_eq!(3, av.threshold().unwrap());
        assert_eq!(4, av.limit().unwrap());

        let tv = ms2.threshold_view().unwrap();
        let ms3 = tv.combine().unwrap();

        assert_eq!(ms1, ms3);
    }

    #[test]
    fn test_eddsa_ssh_roundtrip() {
        let ms1 = Builder::new(Codec::EddsaMsig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let cv = ms1.conv_view().unwrap();
        let ms_ssh = cv.to_ssh_signature().unwrap();
        let ms2 = Builder::new_from_ssh_signature(&ms_ssh)
            .unwrap()
            .try_build()
            .unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_es256k_ssh_roundtrip() {
        let ms1 = Builder::new(Codec::Es256KMsig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let cv = ms1.conv_view().unwrap();
        let ms_ssh = cv.to_ssh_signature().unwrap();
        let ms2 = Builder::new_from_ssh_signature(&ms_ssh)
            .unwrap()
            .try_build()
            .unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_bls_signature_ssh_roundtrip() {
        let sk = blsful::Bls12381G1::new_secret_key();
        let sig = sk
            .sign(
                blsful::SignatureSchemes::ProofOfPossession,
                b"for great justice, move every zig!",
            )
            .unwrap();

        let ms1 = Builder::new_from_bls_signature(&sig)
            .unwrap()
            .try_build()
            .unwrap();

        let cv = ms1.conv_view().unwrap();
        let ssh_ms = cv.to_ssh_signature().unwrap();

        let ms2 = Builder::new_from_ssh_signature(&ssh_ms)
            .unwrap()
            .try_build()
            .unwrap();

        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_bls_signature_combine_ssh_roundtrip() {
        let sk = blsful::Bls12381G2::new_secret_key();
        let sig = sk
            .sign(
                blsful::SignatureSchemes::ProofOfPossession,
                b"for great justice, move every zig!",
            )
            .unwrap();

        let ms1 = Builder::new_from_bls_signature(&sig)
            .unwrap()
            .try_build()
            .unwrap();

        let sk_shares = sk.split(3, 4).unwrap();

        let mut sigs = Vec::default();
        sk_shares.iter().for_each(|sk| {
            let sig = sk
                .sign(
                    blsful::SignatureSchemes::ProofOfPossession,
                    b"for great justice, move every zig!",
                )
                .unwrap();
            sigs.push({
                let ms = Builder::new_from_bls_signature_share(3, 4, &sig)
                    .unwrap()
                    .try_build()
                    .unwrap();
                let sc = ms.conv_view().unwrap();
                sc.to_ssh_signature().unwrap()
            });
        });

        // build a new signature from the parts
        let mut builder = Builder::new(Codec::Bls12381G2Msig);
        for sig in &sigs {
            let ms = Builder::new_from_ssh_signature(sig)
                .unwrap()
                .try_build()
                .unwrap();
            builder = builder.add_signature_share(&ms);
        }
        let ms2 = builder.try_build().unwrap();

        let av = ms2.threshold_attr_view().unwrap();
        assert_eq!(3, av.threshold().unwrap());
        assert_eq!(4, av.limit().unwrap());

        let tv = ms2.threshold_view().unwrap();
        let ms3 = tv.combine().unwrap();

        assert_eq!(ms1, ms3);
    }

    #[test]
    fn test_null() {
        let ms1 = Multisig::null();
        assert!(ms1.is_null());
        let ms2 = Multisig::default();
        assert_eq!(ms1, ms2);
        assert!(ms2.is_null());
    }
}
