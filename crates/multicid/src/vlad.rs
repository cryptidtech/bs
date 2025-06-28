// SPDX-License-Idnetifier: Apache-2.0
use crate::{error::VladError, Cid, Error};
use core::fmt;
use multibase::Base;
use multicodec::Codec;
use multikey::{nonce, Multikey, Nonce, Views};
use multisig::Multisig;
use multitrait::{Null, TryDecodeFrom};
use multiutil::{BaseEncoded, CodecInfo, DetectedEncoder, EncodingInfo};

/// the Vlad multicodec sigil
pub const SIGIL: Codec = Codec::Vlad;

/// a multibase encoded Vlad that can decode from any number of encoding but always encodes to
/// Vlad's preferred Base32Lower multibase encoding (i.e. liberal in what we except, strict in what
/// we generate)
pub type EncodedVlad = BaseEncoded<Vlad, DetectedEncoder>;

/// A verifiable long-lived address (VLAD) represents an identifier for loosely coupled distributed
/// systems that combines a random unique idenitfier (none) with the content address of a
/// verification function in executable format.
///
/// The goal is to avoid the anti-pattern of using public keys as identifiers. Public keys are
/// chosen because they are random and unique enough to be useful identifiers and are also a
/// cryptographic commitment to a validation function--the public key signature validation
/// function. Using public keys as an identifer is an anti-pattern because using key material means
/// that the identifiers are subject to compromise and must be rotated often to maintain security
/// so their "shelf-life" is limited. Rotating and/or abandoning keys due to compromise causes the
/// identifier to become invalid. Any system that stores these identifiers then possesses broken
/// links to the value the identifier is associated with.
///
/// The solution is to realize that we only need a random identifier and a cryptographic commitment
/// to a validation function to replace keys as identifiers. VLADs meet those requirements.
#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Vlad {
    /// the random nonce for uniqueness
    pub(crate) nonce: Nonce,
    /// validation function content address
    pub(crate) cid: Cid,
}

impl Vlad {
    /// Generate a new [Vlad] by signing a [Cid] with the provided signing function
    pub fn generate<F>(cid: &Cid, sign_fn: F) -> Result<Self, Error>
    where
        F: FnOnce(&Cid) -> Result<Vec<u8>, Error>,
    {
        // Get signature bytes by calling the provided signing function
        let signature_bytes = sign_fn(cid)?;

        // Convert signature into a Nonce
        let nonce = nonce::Builder::new_from_bytes(&signature_bytes).build();

        Ok(Self {
            nonce,
            cid: cid.clone(),
        })
    }

    /// Create a Vlad from an existing [Nonce] and [Cid]
    /// This is useful when you already have the signature components
    pub fn from_parts(nonce: Nonce, cid: Cid) -> Self {
        Self { nonce, cid }
    }

    /// verify a Vlad whose nonce is a digital signature over the Cid
    pub fn verify(&self, mk: &Multikey) -> Result<(), Error> {
        let vv = mk.verify_view()?;
        let cidv: Vec<u8> = self.cid.clone().into();
        let ms = Multisig::try_from(self.nonce.as_ref())?;
        vv.verify(&ms, Some(&cidv))?;
        Ok(())
    }

    /// Return the Vlad's [Cid].
    ///
    /// This is the content address of the verification function.
    /// It should match the `vlad/cid` field in a Provenance Log's first Entry.
    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    /// Create an encoded Vlad with the default encoding
    pub fn to_encoded(self) -> EncodedVlad {
        EncodedVlad::new(Self::preferred_encoding(), self)
    }

    /// Create an encoded Vlad with a specific encoding
    pub fn to_encoded_with(self, encoding: Base) -> EncodedVlad {
        EncodedVlad::new(encoding, self)
    }

    /// Attempts to decode a Vlad instance from its [Base] encoded string representation.
    ///
    /// This method takes a string slice and attempts to parse it into an
    /// `EncodedVlad`, and then extracts the inner `Vlad` instance.
    ///
    /// # Arguments
    ///
    /// * `s` - The string representation to decode.
    ///
    /// # Returns
    ///
    /// A `Result` containing a [Vlad] instance if the string is a valid
    /// representation, otherwise an `Error`.
    pub fn try_from_str(s: &str) -> Result<Self, Error> {
        // Parse the string into an EncodedVlad, which handles base decoding
        // and deserialization of the inner Vlad.
        let encoded_vlad = EncodedVlad::try_from(s)?;

        // Extract the inner Vlad instance from the EncodedVlad.
        Ok(encoded_vlad.to_inner())
    }
}

impl CodecInfo for Vlad {
    /// Return that we are a Cid object
    fn preferred_codec() -> Codec {
        SIGIL
    }

    /// Return the codec for this object
    fn codec(&self) -> Codec {
        Self::preferred_codec()
    }
}

impl EncodingInfo for Vlad {
    fn preferred_encoding() -> Base {
        Base::Base32Lower
    }

    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl From<Vlad> for Vec<u8> {
    fn from(vlad: Vlad) -> Vec<u8> {
        let mut v = Vec::default();
        // add the sigil
        v.append(&mut SIGIL.into());
        // add the nonce
        v.append(&mut vlad.nonce.into());
        // add the cid
        v.append(&mut vlad.cid.into());
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for Vlad {
    type Error = Error;

    fn try_from(s: &'a [u8]) -> Result<Self, Self::Error> {
        let (mh, _) = Self::try_decode_from(s)?;
        Ok(mh)
    }
}

impl<'a> TryDecodeFrom<'a> for Vlad {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the sigil
        let (sigil, ptr) = Codec::try_decode_from(bytes)?;
        if sigil != SIGIL {
            return Err(VladError::MissingSigil.into());
        }
        // decode the none
        let (nonce, ptr) = Nonce::try_decode_from(ptr)?;
        // decode the cid
        let (cid, ptr) = Cid::try_decode_from(ptr)?;
        Ok((Self { nonce, cid }, ptr))
    }
}

impl Null for Vlad {
    fn null() -> Self {
        Self {
            nonce: Nonce::null(),
            cid: Cid::null(),
        }
    }

    fn is_null(&self) -> bool {
        *self == Self::null()
    }
}

impl fmt::Debug for Vlad {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} - {:?} - {:?}", SIGIL, self.nonce, self.cid)
    }
}

impl fmt::Display for Vlad {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let encoded = EncodedVlad::new(self.encoding(), self.clone());
        write!(f, "{}", encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid;
    use multihash::mh;
    use multikey::EncodedMultikey;
    use multiutil::{base_name, BaseIter};
    use rng::StdRng;
    use test_log::test;
    use tracing::{span, Level};

    #[test]
    fn test_default() {
        let _s = span!(Level::INFO, "test_default").entered();
        // build a nonce
        let mut rng = StdRng::from_os_rng();
        let nonce = nonce::Builder::new_from_random_bytes(32, &mut rng).build();

        // build a cid
        let cid = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let vlad = Vlad::from_parts(nonce, cid);

        assert_eq!(Codec::Vlad, vlad.codec());
    }

    #[test]
    fn test_binary_roundtrip() {
        let _s = span!(Level::INFO, "test_binary_roundtrip").entered();
        // build a nonce
        let mut rng = StdRng::from_os_rng();
        let nonce = nonce::Builder::new_from_random_bytes(32, &mut rng).build();

        // build a cid
        let cid = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let vlad = Vlad::generate(&cid, |cid| {
            // sign those bytes
            let v: Vec<u8> = cid.clone().into();
            Ok(v)
        })
        .unwrap();

        let v: Vec<u8> = vlad.clone().into();
        //println!("byte len: {}", v.len());
        assert_eq!(vlad, Vlad::try_from(v.as_ref()).unwrap());
    }

    #[test]
    fn test_encoded_roundtrip() {
        let _s = span!(Level::INFO, "test_encoded_roundtrip").entered();
        // build a nonce
        let mut rng = StdRng::from_os_rng();
        let nonce = nonce::Builder::new_from_random_bytes(32, &mut rng).build();

        // build a cid
        let cid = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let vlad = EncodedVlad::new(
            Base::Base32Lower,
            Vlad::generate(&cid, |cid| {
                // sign those bytes
                let v: Vec<u8> = cid.clone().into();
                Ok(v)
            })
            .unwrap(),
        );

        let s = vlad.to_string();
        //println!("({}) {}", s.len(), s);
        assert_eq!(vlad, EncodedVlad::try_from(s.as_str()).unwrap());
    }

    #[test]
    fn test_encodings_roundtrip() {
        let _s = span!(Level::INFO, "test_encodings_roundtrip").entered();
        // build a nonce
        let mut rng = StdRng::from_os_rng();
        let nonce = nonce::Builder::new_from_random_bytes(32, &mut rng).build();

        // build a cid
        let cid = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        // start at Identity so we skip it
        let itr: BaseIter = Base::Identity.into();

        for encoding in itr {
            //print!("{}...", base_name(encoding));
            let vlad = EncodedVlad::new(
                encoding,
                Vlad::generate(&cid, |cid| {
                    // sign those bytes
                    let v: Vec<u8> = cid.clone().into();
                    Ok(v)
                })
                .unwrap(),
            );

            let s = vlad.to_string();
            println!("{}: ({}) {}", base_name(encoding), s.len(), s);
            //println!("worked!");
            assert_eq!(vlad, EncodedVlad::try_from(s.as_str()).unwrap());
        }
    }

    #[test]
    fn test_naked_encodings() {
        let _s = span!(Level::INFO, "test_naked_encodings").entered();
        let naked_encoded = vec![
            (Base::Base2, "0100001110010010010111011001001000010000010101011111101010101001010111011011010101100111011110001011001010000011011111110011110101111000001110010110111101101010001100011010111111110100101011000010111000010011101101111000001111111100011100000001011001011101000101111111111001001001110010010001000000000000101110001000101000100000001010111100100101101101011011001011000001000010110110110000001110110101110001110010011100110001110110101011110001100100100001101000000110011011010111100101010101101111011110100111100100100011100000100110111111000011001100001010010010101001001101010000111100110110100100011111110001001111000100001100010101101001111110110000101110010101001111110001001101110011011100011011110100011110111101010011100101000111001011111001000110010111001000001011010010110101011010010100001101011110011001010100100100000000110111110"),
            (Base::Base8, "74162227311020253752512733254736131203376365701626755214327764530270235570177434013135057771116221000056105040127445553313010266601665616234616653614441500633274525573647444340467703141222511520746644376117041425517660562517611563343364367523450713710627101322653224153631244400676"),
            (Base::Base10, "93870361154591786056205491493019802388883700996012441049219964638855824516737171088563397435615501486404979067615946505439444354740858725022007675555169022360610124101489649907289941930351813344284767475896642016737913366109253497871106880676932034363838"),
            (Base::Base16Lower, "f8724bb2420abf552bb6acef16506fe7af072ded4635fe9585c276f07f8e02cba2ffc939220017114405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be"),
            (Base::Base16Upper, "F8724BB2420ABF552BB6ACEF16506FE7AF072DED4635FE9585C276F07F8E02CBA2FFC939220017114405792DAD96085B6076B8E4E63B578C90D0336BCAADEF4F24704DF866149526A1E6D23F89E218AD3F6172A7E26E6E37A3DEA728E5F232E41696AD286BCCA9201BE"),
            (Base::Base32Lower, "bq4slwjbavp2vfo3kz3ywkbx6plyhfxwumnp6swc4e5xqp6hafs5c77etsiqac4iuiblzfwwzmcc3mb3lrzhghnlyzegqgnv4vlppj4shatpymykjkjvb43jd7cpcdcwt6ylsu7rg43rxuppkokhf6izoifuwvuugxtfjean6"),
            (Base::Base32Upper, "BQ4SLWJBAVP2VFO3KZ3YWKBX6PLYHFXWUMNP6SWC4E5XQP6HAFS5C77ETSIQAC4IUIBLZFWWZMCC3MB3LRZHGHNLYZEGQGNV4VLPPJ4SHATPYMYKJKJVB43JD7CPCDCWT6YLSU7RG43RXUPPKOKHF6IZOIFUWVUUGXTFJEAN6"),
            (Base::Base32HexLower, "vgsibm910lfql5eraproma1nufbo75nmkcdfuim2s4tngfu705it2vv4ji8g02s8k81bp5mmpc22rc1rbhp767dbop46g6dlslbff9si70jfocoa9a9l1sr93v2f232mjuobikvh6srhnkffaea75u8pe85kmlkk6nj5940du"),
            (Base::Base32HexUpper, "VGSIBM910LFQL5ERAPROMA1NUFBO75NMKCDFUIM2S4TNGFU705IT2VV4JI8G02S8K81BP5MMPC22RC1RBHP767DBOP46G6DLSLBFF9SI70JFOCOA9A9L1SR93V2F232MJUOBIKVH6SRHNKFFAEA75U8PE85KMLKK6NJ5940DU"),
            (Base::Base32Z, "hoh1msjbyix4ifq5k35askbz6xma8fzswcpx61snhr7zox68yf17n99ru1eoynhewebm3fss3cnn5cb5mt38g8pma3rgogpihimxxjh18yuxacakjkjibh5jd9nxndnsu6am1w9tgh5tzwxxkqk8f6e3qefwsiwwgzufjryp6"),
            (Base::Base36Lower, "k2xg7x2wm1ycnm2wxuc7edrtm3dz5t7pdojs7qbocom1bg2pzd8vicjuqe8e245npjpvvxtfxfn6qbhvtvkjyxxjccnr6kvnwwa225l8cvyvlv4p8qimjro6awa592cwywrg3ul3lg8orcamiff1jvvi25t4g7698ipq"),
            (Base::Base36Upper, "K2XG7X2WM1YCNM2WXUC7EDRTM3DZ5T7PDOJS7QBOCOM1BG2PZD8VICJUQE8E245NPJPVVXTFXFN6QBHVTVKJYXXJCCNR6KVNWWA225L8CVYVLV4P8QIMJRO6AWA592CWYWRG3UL3LG8ORCAMIFF1JVVI25T4G7698IPQ"),
            (Base::Base58Flickr, "Z3BGq28L4k5syJ5FyzPmBM7pCAYPMKeU1mmgAJcCUSZyBgzMinFA9hxFcDZ65C966no9uGF4C9UqsCmU975d8Bt95XGfZrNTgrWuwPycYHsGn5jyrnaWJtCryzzZErsaffckdav4C42g9bnzy"),
            (Base::Base58Btc, "z3chR28m4L5TZj5gZapMcn7QdbypnkEu1MMGbjCduszZcGanJNgb9HYgCez65d966NP9Vhg4d9uRTdMu975D8cU95xhFzSotGSwVXpZCyiThN5KZSNAwjUdSZaazfSTAFFCLDAW4d42G9BNaZ"),
            (Base::Base64, "mhyS7JCCr9VK7as7xZQb+evBy3tRjX+lYXCdvB/jgLLov/JOSIAFxFEBXktrZYIW2B2uOTmO1eMkNAza8qt708kcE34ZhSVJqHm0j+J4hitP2Fyp+Jubjej3qco5fIy5BaWrShrzKkgG+"),
            (Base::Base64Url, "uhyS7JCCr9VK7as7xZQb-evBy3tRjX-lYXCdvB_jgLLov_JOSIAFxFEBXktrZYIW2B2uOTmO1eMkNAza8qt708kcE34ZhSVJqHm0j-J4hitP2Fyp-Jubjej3qco5fIy5BaWrShrzKkgG-"),
            (Base::Base256Emoji, "🚀🙊🥰😙🥰😅🤨🤐❣😙😬😟💩✋🌒📣💐💡🥺🐷📌💃🥳💣💥😡💙😓🌓🥵💧💪🤓👌👼😫🌼😅🪐✅💾😋😑🌼😗🍒😥🖕🤬🌓🙃🤞👇💃💨😣🦋🌍🛰🤦💟😰🐷👻👐🤩🌌☎💝🤤😀❣😬😘🌷🔥🥵🐶👏💫🤧🤮❤😆😠💖🍑👆💐😌🐸🥺🤞🥳🔥☺💗🌟😬🤠💝💟😷🌼🪐😖")
        ];

        for naked in naked_encoded {
            print!("{}...", base_name(naked.0));
            let vlad = EncodedVlad::try_from(naked.1).unwrap();
            assert_eq!(naked.0, vlad.encoding());
            println!("worked!!");
        }
    }

    #[test]
    fn test_signed_vlad() {
        let _s = span!(Level::INFO, "test_signed_vlad").entered();
        // build a cid
        let cid = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let s = "fba2480260874657374206b657901012064e58adf88f85cbec6a0448a0803f9d28cf9231a7141be413f83cf6aa883cd04";
        let mk = EncodedMultikey::try_from(s).unwrap();

        let vlad = EncodedVlad::new(
            Base::Base32Z,
            Vlad::generate(&cid, |cid| {
                // use mk to sign those cid bytes
                let signing_view = mk.sign_view()?;
                let cidv: Vec<u8> = cid.clone().into();
                let ms = signing_view.sign(&cidv, false, None)?;
                let msv: Vec<u8> = ms.clone().into();
                Ok(msv)
            })
            .unwrap(),
        );

        // make sure the signature checks out
        assert!(vlad.verify(&mk).is_ok());
        let s = vlad.to_string();
        //println!("BASE32Z ({}) {}", s.len(), s);
        let de = EncodedVlad::try_from(s.as_str()).unwrap();
        assert_eq!(vlad, de);
        assert_eq!(Base::Base32Z, de.encoding());
        let vlad = vlad.to_inner();
        let v: Vec<u8> = vlad.clone().into();
        //println!("BLAH: {}", hex::encode(&v));
        assert_eq!(vlad, Vlad::try_from(v.as_ref()).unwrap());
    }

    #[test]
    fn test_null() {
        let _s = span!(Level::INFO, "test_null").entered();
        let v1 = Vlad::null();
        assert!(v1.is_null());
        let v2 = Vlad::default();
        assert!(v1 != v2);
        assert!(!v2.is_null());
    }

    // test impl fmt::Display for Vlad
    #[test]
    fn test_display() {
        let _s = span!(Level::INFO, "test_display").entered();
        // build a nonce
        let mut rng = StdRng::from_os_rng();
        let nonce = nonce::Builder::new_from_random_bytes(32, &mut rng).build();

        // build a cid
        let cid = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let vlad = Vlad::from_parts(nonce, cid);

        eprintln!("vlad: {}", vlad);

        assert!(!vlad.to_string().is_empty());
    }
}
