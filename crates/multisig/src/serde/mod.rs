// SPDX-License-Idnetifier: Apache-2.0
//! Serde (de)serialization for [`crate::Varsig`].
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::{Builder, EncodedMultisig, Multisig};
    use multibase::Base;
    use multicodec::Codec;
    use multitrait::Null;
    use serde_test::{assert_tokens, Configure, Token};

    #[test]
    fn test_ed25519_serde_compact() {
        let ms = Builder::new(Codec::Eddsa)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();

        assert_tokens(
            &ms.compact(),
            &[
                Token::BorrowedBytes(&[185, 36, 237, 161, 3, 0, 1, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            ],
        )
    }

    #[test]
    fn test_ed25519_serde_encoded_string() {
        let ms = Builder::new(Codec::Eddsa)
            .with_signature_bytes(&[0u8; 64])
            .with_base_encoding(Base::Base58Btc)
            .try_build_encoded()
            .unwrap();

        assert_tokens(
            &ms.readable(),
            &[Token::BorrowedStr("zD4bHwUem3jQTfFd82d2koBo7sa2cAr9mvAJcXEVSAPe8mjDHRaGRYYjFmphxaAsUhENDevuR7J3xtWpW41pqEKrpMQfkZEwFopdm")
            ],
        )
    }

    #[test]
    fn test_ed25519_serde_readable() {
        let ms = Builder::new(Codec::Eddsa)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();

        assert_tokens(
            &ms.readable(),
            &[
                Token::Struct {
                    name: "multisig",
                    len: 3,
                },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("eddsa"),
                Token::BorrowedStr("message"),
                Token::BorrowedStr("f00"),
                Token::BorrowedStr("attributes"),
                Token::Seq { len: Some(1) },
                Token::Tuple { len: 2 },
                Token::BorrowedStr("sig-data"),
                Token::BorrowedStr("f4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
                Token::TupleEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        )
    }

    #[test]
    fn test_ed25519_serde_json() {
        let ms1 = Builder::new(Codec::Eddsa)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let s = serde_json::to_string(&ms1).unwrap();
        let ms2: Multisig = serde_json::from_str(&s).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_ed25519_serde_cbor() {
        let ms1 = Builder::new(Codec::Eddsa)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let v = serde_cbor::to_vec(&ms1).unwrap();
        let ms2: Multisig = serde_cbor::from_slice(v.as_slice()).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_secp256k1_serde_compact() {
        let ms = Builder::new(Codec::Es256K)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();

        assert_tokens(
            &ms.compact(),
            &[
                Token::BorrowedBytes(&[185, 36, 231, 161, 3, 0, 1, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            ],
        )
    }

    #[test]
    fn test_secp256k1_serde_encoded_string() {
        let ms = Builder::new(Codec::Es256K)
            .with_signature_bytes(&[0u8; 64])
            .with_base_encoding(Base::Base58Btc)
            .try_build_encoded()
            .unwrap();

        assert_tokens(
            &ms.readable(),
            &[Token::BorrowedStr("zD4bGmynFsniw14r8UfRGjEvoBEGLXGSRh69iptfk43kLUGCLhXMFVmkmLXWoj9AzWGXpG183NV8jXNdsKwY8bJVKDRhWnkUV9w6f")
            ],
        )
    }

    #[test]
    fn test_secp256k1_serde_readable() {
        let ms = Builder::new(Codec::Es256K)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();

        assert_tokens(
            &ms.readable(),
            &[
                Token::Struct {
                    name: "multisig",
                    len: 3,
                },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("es256k"),
                Token::BorrowedStr("message"),
                Token::BorrowedStr("f00"),
                Token::BorrowedStr("attributes"),
                Token::Seq { len: Some(1) },
                Token::Tuple { len: 2 },
                Token::BorrowedStr("sig-data"),
                Token::BorrowedStr("f4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
                Token::TupleEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        )
    }

    #[test]
    fn test_secp256k1_serde_json() {
        let ms1 = Builder::new(Codec::Es256K)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let s = serde_json::to_string(&ms1).unwrap();
        let ms2: Multisig = serde_json::from_str(&s).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_secp256k1_serde_cbor() {
        let ms1 = Builder::new(Codec::Es256K)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let v = serde_cbor::to_vec(&ms1).unwrap();
        let ms2: Multisig = serde_cbor::from_slice(v.as_slice()).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_bls12381g1_serde_compact() {
        /*
        let ms = Builder::new(Codec::Bls12381G1Msig)
            .with_signature_bytes(&[0u8; 64])
            .with_base_encoding(Base::Base58Btc)
            .try_build_encoded()
            .unwrap();
        println!("encoded bls multisig: {}", ms);
        */

        let ms = EncodedMultisig::try_from(
            "zvEpmKysTLofqideRPss5Rxttsnxkkom2xvwxZ3diG5NCWR3NZpE2qxvjyTBVAyo86smZ1sk3k6wvibxJhyU8LrsLR2x16cukcjSLF",
        )
        .unwrap()
        .to_inner();

        assert_tokens(
            &ms.compact(),
            &[
                Token::BorrowedBytes(&[185, 36, 129, 166, 192, 6, 0, 1, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            ],
        )
    }

    #[test]
    fn test_bls12381g1_serde_encoded_string() {
        let ms = EncodedMultisig::try_from(
            "zvEpmKysTLofqideRPss5Rxttsnxkkom2xvwxZ3diG5NCWR3NZpE2qxvjyTBVAyo86smZ1sk3k6wvibxJhyU8LrsLR2x16cukcjSLF",
        )
        .unwrap();

        assert_tokens(
            &ms.readable(),
            &[Token::BorrowedStr(
                "zvEpmKysTLofqideRPss5Rxttsnxkkom2xvwxZ3diG5NCWR3NZpE2qxvjyTBVAyo86smZ1sk3k6wvibxJhyU8LrsLR2x16cukcjSLF",
            )],
        )
    }

    #[test]
    fn test_bls12381g1_serde_readable() {
        let ms = EncodedMultisig::try_from(
            "zvEpmKysTLofqideRPss5Rxttsnxkkom2xvwxZ3diG5NCWR3NZpE2qxvjyTBVAyo86smZ1sk3k6wvibxJhyU8LrsLR2x16cukcjSLF",
        )
        .unwrap()
        .to_inner();

        assert_tokens(
            &ms.readable(),
            &[
                Token::Struct {
                    name: "multisig",
                    len: 3,
                },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("bls12_381-g1-msig"),
                Token::BorrowedStr("message"),
                Token::BorrowedStr("f00"),
                Token::BorrowedStr("attributes"),
                Token::Seq { len: Some(1) },
                Token::Tuple { len: 2 },
                Token::BorrowedStr("sig-data"),
                Token::BorrowedStr("f4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
                Token::TupleEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        )
    }

    #[test]
    fn test_bls12381g1_serde_json() {
        let ms1 = Builder::new(Codec::Bls12381G1Msig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let s = serde_json::to_string(&ms1).unwrap();
        let ms2: Multisig = serde_json::from_str(&s).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_bls12381g1_serde_cbor() {
        let ms1 = Builder::new(Codec::Bls12381G1Msig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let v = serde_cbor::to_vec(&ms1).unwrap();
        let ms2: Multisig = serde_cbor::from_slice(v.as_slice()).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_bls12381g1_share_serde_compact() {
        let ms = Builder::new(Codec::Bls12381G1Msig)
            .with_signature_bytes(&[0u8; 64])
            .with_base_encoding(Base::Base58Btc)
            .try_build_encoded()
            .unwrap();
        println!("encoded bls multisig: {}", ms);

        let ms = EncodedMultisig::try_from(
            "hzr1ejjsyyayykybounzzo85hy3tfkhe19ro6k973bknezbqysqm4u9oax7yfx5t6wnuyz6rnfym7zttnrfajamxdoy91hyobyebonyaryrnykyeb",
        )
        .unwrap()
        .to_inner();

        assert_eq!(Codec::Bls12381G1ShareMsig, ms.codec);

        /*
        let v: Vec<u8> = ms.clone().into();
        print!("BLAH: ");
        for b in &v {
            print!("0x{:02x}, ", b);
        }
        println!("");
        */

        assert_tokens(
            &ms.compact(),
            &[
                Token::BorrowedBytes(&[185, 36, 132, 166, 192, 6, 0, 5, 0, 48, 152, 175, 120, 31, 124, 6, 98, 85, 113, 18, 249, 33, 229, 127, 185, 10, 132, 139, 133, 192, 179, 151, 169, 254, 24, 127, 64, 87, 238, 62, 160, 166, 11, 248, 130, 40, 23, 219, 198, 34, 33, 112, 156, 45, 227, 128, 63, 46, 2, 1, 2, 3, 1, 3, 4, 1, 4, 5, 1, 1])
            ],
        )
    }

    #[test]
    fn test_bls12381g1_share_serde_encoded_string() {
        let ms = EncodedMultisig::try_from(
            "hzr1ejjsyyayykybounzzo85hy3tfkhe19ro6k973bknezbqysqm4u9oax7yfx5t6wnuyz6rnfym7zttnrfajamxdoy91hyobyebonyaryrnykyeb",
        )
        .unwrap();

        assert_tokens(
            &ms.readable(),
            &[
                Token::BorrowedStr("hzr1ejjsyyayykybounzzo85hy3tfkhe19ro6k973bknezbqysqm4u9oax7yfx5t6wnuyz6rnfym7zttnrfajamxdoy91hyobyebonyaryrnykyeb")
            ],
        )
    }

    #[test]
    fn test_bls12381g1_share_serde_readable() {
        let ms = EncodedMultisig::try_from(
            "hzr1ejjsyyayykybounzzo85hy3tfkhe19ro6k973bknezbqysqm4u9oax7yfx5t6wnuyz6rnfym7zttnrfajamxdoy91hyobyebonyaryrnykyeb",
        )
        .unwrap()
        .to_inner();

        assert_tokens(
            &ms.readable(),
            &[
                Token::Struct { name: "multisig", len: 3, },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("bls12_381-g1-share-msig"),
                Token::BorrowedStr("message"),
                Token::BorrowedStr("f00"),
                Token::BorrowedStr("attributes"),
                Token::Seq { len: Some(5) },
                Token::Tuple { len: 2 },
                Token::BorrowedStr("sig-data"),
                Token::BorrowedStr("f3098af781f7c0662557112f921e57fb90a848b85c0b397a9fe187f4057ee3ea0a60bf8822817dbc62221709c2de3803f2e"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("scheme"),
                Token::BorrowedStr("f0102"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("threshold"),
                Token::BorrowedStr("f0103"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("limit"),
                Token::BorrowedStr("f0104"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("share-identifier"),
                Token::BorrowedStr("f0101"),
                Token::TupleEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        )
    }

    #[test]
    fn test_bls12381g1_share_serde_json() {
        let ms1 = EncodedMultisig::try_from(
            "hzr1ejjsyyayykybounzzo85hy3tfkhe19ro6k973bknezbqysqm4u9oax7yfx5t6wnuyz6rnfym7zttnrfajamxdoy91hyobyebonyaryrnykyeb",
        )
        .unwrap()
        .to_inner();

        let s = serde_json::to_string(&ms1).unwrap();
        let ms2: Multisig = serde_json::from_str(&s).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_bls12381g1_share_serde_cbor() {
        let ms1 = EncodedMultisig::try_from(
            "hzr1ejjsyyayykybounzzo85hy3tfkhe19ro6k973bknezbqysqm4u9oax7yfx5t6wnuyz6rnfym7zttnrfajamxdoy91hyobyebonyaryrnykyeb",
        )
        .unwrap()
        .to_inner();

        let v = serde_cbor::to_vec(&ms1).unwrap();
        let ms2: Multisig = serde_cbor::from_slice(v.as_slice()).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_null_multisig_serde_compact() {
        let ms = Multisig::null();
        assert_tokens(
            &ms.compact(),
            &[
                Token::BorrowedBytes(&[185, 36, 0, 0, 0])
            ],
        );
    }

    #[test]
    fn test_null_multisig_serde_readable() {
        let ms = Multisig::null();
        assert_tokens(
            &ms.readable(),
            &[
                Token::Struct { name: "multisig", len: 3, },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("identity"),
                Token::BorrowedStr("message"),
                Token::BorrowedStr("f00"),
                Token::BorrowedStr("attributes"),
                Token::Seq { len: Some(0) },
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_encoded_null_multisig_serde_readable() {
        let ms: EncodedMultisig = Multisig::null().into();
        assert_tokens(
            &ms.readable(),
            &[
                Token::BorrowedStr("fb924000000"),
            ],
        );
    }
}
