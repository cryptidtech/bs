// SPDX-License-Idnetifier: Apache-2.0
//! Serde (de)serialization for [`crate::Cid`] and [`crate::Vlad`]
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::{cid, vlad};
    use multicodec::Codec;
    use multihash::mh;
    use multikey::nonce;
    use multitrait::Null;
    use serde_test::{assert_tokens, Configure, Token};

    #[test]
    fn test_cidv0_serde_encoded_string() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build_legacy_encoded()
            .unwrap();

        assert_tokens(
            &v0.readable(),
            &[Token::BorrowedStr(
                "Qmdb16CztyugMSs5anEPrJ6bLeo39bTGcM13zNPqjqUidT",
            )],
        );
    }

    #[test]
    fn test_cidv0_serde_readable() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        assert_tokens(
            &v0.readable(),
            &[
                Token::Struct { name: "cid", len: 3, },
                Token::BorrowedStr("version"),
                Token::U64(0),
                Token::BorrowedStr("encoding"),
                Token::BorrowedStr("dag-pb"),
                Token::BorrowedStr("hash"),
                Token::Struct { name: "multihash", len: 2, },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("sha2-256"),
                Token::BorrowedStr("hash"),
                Token::BorrowedStr("f20e28c7aeb3a876b25ed822472e47a696fe25214c1672f0972195f9b64eea41e7e"),
                Token::StructEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_cidv0_serde_json() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let s = serde_json::to_string(&v0).unwrap();
        assert_eq!(s, "{\"version\":0,\"encoding\":\"dag-pb\",\"hash\":{\"codec\":\"sha2-256\",\"hash\":\"f20e28c7aeb3a876b25ed822472e47a696fe25214c1672f0972195f9b64eea41e7e\"}}");
        assert_eq!(v0, serde_json::from_str(&s).unwrap());
    }

    #[cfg(not(feature = "dag_cbor"))]
    #[test]
    fn test_cidv0_serde_cbor() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let v = serde_cbor::to_vec(&v0).unwrap();
        //println!("{}", hex::encode(&v));
        assert_eq!(
            v,
            hex::decode("58221220e28c7aeb3a876b25ed822472e47a696fe25214c1672f0972195f9b64eea41e7e")
                .unwrap()
        );
        assert_eq!(v0, serde_cbor::from_slice(&v).unwrap());
    }

    #[cfg(feature = "dag_cbor")]
    #[test]
    fn test_cidv0_serde_dag_cbor() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let v = serde_cbor::to_vec(&v0).unwrap();
        //println!("{}", hex::encode(&v));
        assert_eq!(
            v,
            hex::decode(
                "d82a5823001220e28c7aeb3a876b25ed822472e47a696fe25214c1672f0972195f9b64eea41e7e"
            )
            .unwrap()
        );
        assert_eq!(v0, serde_cbor::from_slice(&v).unwrap());
    }

    #[test]
    fn test_cidv1_serde_encoded_string() {
        let v1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build_encoded()
            .unwrap();

        assert_tokens(
            &v1.readable(),
            &[Token::BorrowedStr(
                "zBwWX6osYqv4RE9txKLpnJsiQ9kKAdRhhkmeBvsQtFVw69VXwfhxiBxstMsNXbuhsCqKoppSS3GPKQBW3tWB4CtUNUTo3"
            )],
        );
    }

    #[test]
    fn test_cidv1_serde_readable() {
        let v1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::DagCbor)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        assert_tokens(
            &v1.readable(),
            &[
                Token::Struct {
                    name: "cid",
                    len: 3,
                },
                Token::BorrowedStr("version"),
                Token::U64(1),
                Token::BorrowedStr("encoding"),
                Token::BorrowedStr("dag-cbor"),
                Token::BorrowedStr("hash"),
                Token::Struct { name: "multihash", len: 2, },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("sha3-512"),
                Token::BorrowedStr("hash"),
                Token::BorrowedStr("f405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be"),
                Token::StructEnd,
                Token::StructEnd,
            ],
        );
    }

    #[cfg(not(feature = "dag_cbor"))]
    #[test]
    fn test_cidv1_serde_cbor() {
        let v1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::Raw)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let v = serde_cbor::to_vec(&v1).unwrap();
        //println!("{}", hex::encode(&v));
        assert_eq!(
            v,
            hex::decode(
                "582401551220e28c7aeb3a876b25ed822472e47a696fe25214c1672f0972195f9b64eea41e7e"
            )
            .unwrap()
        );
        assert_eq!(v1, serde_cbor::from_slice(&v).unwrap());
    }

    #[cfg(feature = "dag_cbor")]
    #[test]
    fn test_cidv1_serde_dag_cbor() {
        let v1 = cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::Raw)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let v = serde_cbor::to_vec(&v1).unwrap();
        //println!("{}", hex::encode(&v));
        assert_eq!(v, hex::decode("d82a58250001551220e28c7aeb3a876b25ed822472e47a696fe25214c1672f0972195f9b64eea41e7e").unwrap());
        assert_eq!(v1, serde_cbor::from_slice(&v).unwrap());
    }

    #[test]
    fn test_vlad_serde_encoded_string() {
        let bytes = hex::decode("d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832")
            .unwrap();
        let nonce = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

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

        let vlad = vlad::Builder::default()
            .with_nonce(&nonce)
            .with_cid(&cid)
            .try_build_encoded()
            .unwrap();

        assert_tokens(
            &vlad.readable(),
            &[Token::BorrowedStr("bq4slwjba2foe7murdlqtg7yqfpfpjqairu3diw4iwjbzndudjrp7uf4qpazac4iuiblzfwwzmcc3mb3lrzhghnlyzegqgnv4vlppj4shatpymykjkjvb43jd7cpcdcwt6ylsu7rg43rxuppkokhf6izoifuwvuugxtfjean6"),
            ],
        );
    }

    #[test]
    fn test_vlad_serde_readable() {
        let bytes = hex::decode("d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832")
            .unwrap();
        let nonce = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

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

        let vlad = vlad::Builder::default()
            .with_nonce(&nonce)
            .with_cid(&cid)
            .try_build()
            .unwrap();

        assert_tokens(
            &vlad.readable(),
            &[
                Token::Struct {
                    name: "vlad",
                    len: 2,
                },
                Token::BorrowedStr("nonce"),
                Token::Struct {
                    name: "nonce",
                    len: 1,
                },
                Token::BorrowedStr("nonce"),
                Token::BorrowedStr(
                    "f20d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832",
                ),
                Token::StructEnd,
                Token::BorrowedStr("cid"),
                Token::Struct {
                    name: "cid",
                    len: 3,
                },
                Token::BorrowedStr("version"),
                Token::U64(1),
                Token::BorrowedStr("encoding"),
                Token::BorrowedStr("dag-cbor"),
                Token::BorrowedStr("hash"),
                Token::Struct { name: "multihash", len: 2, },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("sha3-512"),
                Token::BorrowedStr("hash"),
                Token::BorrowedStr("f405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be"),
                Token::StructEnd,
                Token::StructEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_vlad_serde_json() {
        let bytes = hex::decode("d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832")
            .unwrap();
        let nonce = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

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

        let vlad = vlad::Builder::default()
            .with_nonce(&nonce)
            .with_cid(&cid)
            .try_build()
            .unwrap();

        let s = serde_json::to_string(&vlad).unwrap();
        assert_eq!(s, "{\"nonce\":{\"nonce\":\"f20d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832\"},\"cid\":{\"version\":1,\"encoding\":\"dag-cbor\",\"hash\":{\"codec\":\"sha3-512\",\"hash\":\"f405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be\"}}}");
        assert_eq!(vlad, serde_json::from_str(&s).unwrap());
    }

    #[cfg(not(feature = "dag_cbor"))]
    #[test]
    fn test_vlad_serde_cbor() {
        let bytes = hex::decode("d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832")
            .unwrap();
        let nonce = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

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

        let vlad = vlad::Builder::default()
            .with_nonce(&nonce)
            .with_cid(&cid)
            .try_build()
            .unwrap();

        let v = serde_cbor::to_vec(&vlad).unwrap();
        //println!("serde_cbor vlad: {}", hex::encode(&v));
        assert_eq!(v, hex::decode("58698724bb2420d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832017114405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be").unwrap());
        assert_eq!(vlad, serde_cbor::from_slice(&v).unwrap());
    }

    #[cfg(feature = "dag_cbor")]
    #[test]
    fn test_vlad_serde_dag_cbor() {
        let bytes = hex::decode("d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832")
            .unwrap();
        let nonce = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

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

        let vlad = vlad::Builder::default()
            .with_nonce(&nonce)
            .with_cid(&cid)
            .try_build()
            .unwrap();

        let v = serde_cbor::to_vec(&vlad).unwrap();
        //println!("{}", hex::encode(&v));
        assert_eq!(v, hex::decode("83410782413b582120d15c4fb2911ae1337f102bcaf4c0088d36345b88b243968e834c5ffa17907832d82a584500017114405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be").unwrap());
        assert_eq!(vlad, serde_cbor::from_slice(&v).unwrap());
    }

    #[test]
    fn test_null_cid_serde_compact() {
        let c = cid::Cid::null();
        assert_tokens(
            &c.compact(),
            &[
                Token::BorrowedBytes(&[1, 0, 0, 0])
            ]
        );
    }

    #[test]
    fn test_null_cid_serde_readable() {
        let c = cid::Cid::null();
        assert_tokens(
            &c.readable(),
            &[
                Token::Struct { name: "cid", len: 3, },
                Token::BorrowedStr("version"),
                Token::U64(1),
                Token::BorrowedStr("encoding"),
                Token::BorrowedStr("identity"),
                Token::BorrowedStr("hash"),
                Token::Struct { name: "multihash", len: 2, },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("identity"),
                Token::BorrowedStr("hash"),
                Token::BorrowedStr("f00"),
                Token::StructEnd,
                Token::StructEnd,
            ]
        );
    }

    #[test]
    fn test_encoded_null_cid_serde_readable() {
        let c: cid::EncodedCid = cid::Cid::null().into();
        assert_tokens(
            &c.readable(),
            &[
                Token::BorrowedStr("z2UzHM"),
            ]
        );
    }

    #[test]
    fn test_null_vlad_serde_compact() {
        let v = vlad::Vlad::null();
        assert_tokens(
            &v.compact(),
            &[
                Token::BorrowedBytes(&[135, 36, 187, 36, 0, 1, 0, 0, 0]),
            ]
        );
    }

    #[test]
    fn test_null_vlad_serde_readable() {
        let v = vlad::Vlad::null();
        assert_tokens(
            &v.readable(),
            &[
                Token::Struct { name: "vlad", len: 2, },
                Token::BorrowedStr("nonce"),
                Token::Struct { name: "nonce", len: 1, },
                Token::BorrowedStr("nonce"),
                Token::BorrowedStr("f00"),
                Token::StructEnd,
                Token::BorrowedStr("cid"),
                Token::Struct { name: "cid", len: 3, },
                Token::BorrowedStr("version"),
                Token::U64(1),
                Token::BorrowedStr("encoding"),
                Token::BorrowedStr("identity"),
                Token::BorrowedStr("hash"),
                Token::Struct { name: "multihash", len: 2, },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("identity"),
                Token::BorrowedStr("hash"),
                Token::BorrowedStr("f00"),
                Token::StructEnd,
                Token::StructEnd,
                Token::StructEnd,
            ]
        );
    }

    #[test]
    fn test_encoded_null_vlad_serde_readable() {
        let v: vlad::EncodedVlad = vlad::Vlad::null().into();
        assert_tokens(
            &v.readable(),
            &[
                Token::BorrowedStr("bq4slwjaaaeaaaaa"),
            ]
        );
    }
}
