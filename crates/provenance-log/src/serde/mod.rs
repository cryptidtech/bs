// SPDX-License-Identifier: FSL-1.1
//! Serde (de)serialization for provenance log types
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::{entry, Key, Op, Script, Value};
    use multicid::{cid, vlad};
    use multicodec::Codec;
    use multihash::mh;
    use multikey::nonce;
    use serde_test::{assert_tokens, Configure, Token};

    #[test]
    fn test_value_default_compact() {
        let v = Value::default();
        assert_tokens(
            &v.compact(),
            &[
                Token::BorrowedBytes(&[0]),
            ],
        );
    }

    #[test]
    fn test_value_default_readable() {
        let v = Value::default();
        assert_tokens(
            &v.readable(),
            &[Token::UnitVariant {
                name: "value",
                variant: "nil",
            }],
        );
    }

    #[test]
    fn test_value_default_json() {
        let v = Value::default();
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, "\"nil\"".to_string());
        assert_eq!(v, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_value_default_cbor() {
        let v = Value::default();
        let b = serde_cbor::to_vec(&v).unwrap();
        assert_eq!(b, vec![65, 0]);
        assert_eq!(v, serde_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_value_str_compact() {
        let v = Value::Str("move zig!".into());
        assert_tokens(
            &v.compact(),
            &[
                Token::BorrowedBytes(&[
                    1, 9, 109, 111, 118, 101, 32, 122, 105, 103, 33
                ])
            ],
        );
    }

    #[test]
    fn test_value_str_readable() {
        let v = Value::Str("move zig!".into());
        assert_tokens(
            &v.readable(),
            &[
                Token::TupleVariant {
                    name: "value",
                    variant: "str",
                    len: 1,
                },
                Token::BorrowedStr("move zig!"),
                Token::TupleVariantEnd,
            ],
        );
    }

    #[test]
    fn test_value_str_json() {
        let v = Value::Str("move zig!".into());
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, "{\"str\":[\"move zig!\"]}".to_string());
        assert_eq!(v, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_value_str_cbor() {
        let v = Value::Str("move zig!".into());
        let b = serde_cbor::to_vec(&v).unwrap();
        assert_eq!(b, vec![75, 1, 9, 109, 111, 118, 101, 32, 122, 105, 103, 33]);
        assert_eq!(v, serde_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_op_default_compact() {
        let o = Op::default();
        assert_tokens(
            &o.compact(),
            &[
                Token::BorrowedBytes(&[0, 1, 47]),
            ],
        );
    }

    #[test]
    fn test_op_default_readable() {
        let o = Op::default();
        assert_tokens(
            &o.readable(),
            &[
                Token::TupleVariant { name: "op", variant: "noop", len: 1 },
                Token::BorrowedStr("/"),
                Token::TupleVariantEnd,
            ],
        );
    }

    #[test]
    fn test_op_default_json() {
        let o = Op::default();
        let s = serde_json::to_string(&o).unwrap();
        assert_eq!(s, "{\"noop\":[\"/\"]}".to_string());
        assert_eq!(o, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_op_default_cbor() {
        let o = Op::default();
        let b = serde_cbor::to_vec(&o).unwrap();
        assert_eq!(b, vec![67, 0, 1, 47]);
        assert_eq!(o, serde_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_op_delete_compact() {
        let o = Op::Delete("/zig".try_into().unwrap());
        assert_tokens(
            &o.compact(),
            &[
                Token::BorrowedBytes(&[1, 4, 47, 122, 105, 103]),
            ],
        );
    }

    #[test]
    fn test_op_delete_readable() {
        let o = Op::Delete("/zig".try_into().unwrap());
        assert_tokens(
            &o.readable(),
            &[
                Token::TupleVariant {
                    name: "op",
                    variant: "delete",
                    len: 1,
                },
                Token::BorrowedStr("/zig"),
                Token::TupleVariantEnd,
            ],
        );
    }

    #[test]
    fn test_op_delete_json() {
        let o = Op::Delete("/zig".try_into().unwrap());
        let s = serde_json::to_string(&o).unwrap();
        assert_eq!(s, "{\"delete\":[\"/zig\"]}".to_string());
        assert_eq!(o, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_op_update_json() {
        let o = Op::Update("/move".try_into().unwrap(), Value::Str("zig".into()));
        let s = serde_json::to_string(&o).unwrap();
        assert_eq!(s, "{\"update\":[\"/move\",{\"str\":[\"zig\"]}]}".to_string());
        assert_eq!(o, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_op_update_data_value_json() {
        let o = Op::Update("/move".try_into().unwrap(), Value::Data(vec![1]));
        let s = serde_json::to_string(&o).unwrap();
        assert_eq!(
            s,
            "{\"update\":[\"/move\",{\"data\":[\"f0101\"]}]}".to_string()
        );
        assert_eq!(o, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_op_update_default_value_json() {
        let o = Op::Update("/move".try_into().unwrap(), Value::default());
        let s = serde_json::to_string(&o).unwrap();
        assert_eq!(s, "{\"update\":[\"/move\",\"nil\"]}".to_string());
        assert_eq!(o, serde_json::from_str(&s).unwrap());
    }
    #[test]
    fn test_op_delete_cbor() {
        let o = Op::Delete("/zig".try_into().unwrap());
        let b = serde_cbor::to_vec(&o).unwrap();
        assert_eq!(b, vec![70, 1, 4, 47, 122, 105, 103]);
        assert_eq!(o, serde_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_script_default_compact() {
        let s = Script::default();
        assert_tokens(
            &s.compact(),
            &[
                Token::BorrowedBytes(&[138, 36, 0, 1, 47, 0]),
            ],
        );
    }

    #[test]
    fn test_script_default_readable() {
        let s = Script::default();
        assert_tokens(
            &s.readable(),
            &[
                Token::TupleVariant {
                    name: "provenance-log-script",
                    variant: "bin",
                    len: 2,
                },
                Token::BorrowedStr("/"),
                Token::BorrowedStr("f00"),
                Token::TupleVariantEnd,
            ],
        );
    }

    #[test]
    fn test_script_default_json() {
        let t = Script::default();
        let s = serde_json::to_string(&t).unwrap();
        assert_eq!(s, "{\"bin\":[\"/\",\"f00\"]}".to_string());
        assert_eq!(t, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_script_default_cbor() {
        let s = Script::default();
        let b = serde_cbor::to_vec(&s).unwrap();
        assert_eq!(b, vec![70, 138, 36, 0, 1, 47, 0]);
        assert_eq!(s, serde_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_script_cidv0_compact() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let s = Script::Cid(Key::default(), v0);
        assert_tokens(
            &s.compact(),
            &[
                Token::BorrowedBytes(&[138, 36, 2, 1, 47, 18, 32, 226, 140, 122, 235, 58, 135, 107, 37, 237, 130, 36, 114, 228, 122, 105, 111, 226, 82, 20, 193, 103, 47, 9, 114, 25, 95, 155, 100, 238, 164, 30, 126])
            ]
            ,
        );
    }

    #[test]
    fn test_script_cidv0_readable() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let s = Script::Cid(Key::default(), v0);
        assert_tokens(
            &s.readable(),
            &[
                Token::TupleVariant { name: "provenance-log-script", variant: "cid", len: 2, },
                Token::BorrowedStr("/"),
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
                Token::TupleVariantEnd,
            ],
        );
    }

    #[test]
    fn test_script_cidv0_json() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let t = Script::Cid(Key::default(), v0);
        let s = serde_json::to_string(&t).unwrap();
        assert_eq!(s, "{\"cid\":[\"/\",{\"version\":0,\"encoding\":\"dag-pb\",\"hash\":{\"codec\":\"sha2-256\",\"hash\":\"f20e28c7aeb3a876b25ed822472e47a696fe25214c1672f0972195f9b64eea41e7e\"}}]}");
        assert_eq!(t, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_script_cidv0_cbor() {
        let v0 = cid::Builder::default()
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha2256, b"for great justice, move every zig!")
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap();

        let s = Script::Cid(Key::default(), v0);
        let b = serde_cbor::to_vec(&s).unwrap();
        assert_eq!(b, vec![88, 39, 138, 36, 2, 1, 47, 18, 32, 226, 140, 122, 235, 58, 135, 107, 37, 237, 130, 36, 114, 228, 122, 105, 111, 226, 82, 20, 193, 103, 47, 9, 114, 25, 95, 155, 100, 238, 164, 30, 126]);
        assert_eq!(s, serde_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_script_cidv1_compact() {
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

        let s = Script::Cid(Key::default(), v1);
        assert_tokens(
            &s.compact(),
            &[
                Token::BorrowedBytes(&[138, 36, 2, 1, 47, 1, 113, 20, 64, 87, 146, 218, 217, 96, 133, 182, 7, 107, 142, 78, 99, 181, 120, 201, 13, 3, 54, 188, 170, 222, 244, 242, 71, 4, 223, 134, 97, 73, 82, 106, 30, 109, 35, 248, 158, 33, 138, 211, 246, 23, 42, 126, 38, 230, 227, 122, 61, 234, 114, 142, 95, 35, 46, 65, 105, 106, 210, 134, 188, 202, 146, 1, 190]),
            ],
        );
    }

    #[test]
    fn test_script_cidv1_readable() {
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

        let s = Script::Cid(Key::default(), v1);
        assert_tokens(
            &s.readable(),
            &[
                Token::TupleVariant { name: "provenance-log-script", variant: "cid", len: 2, },
                Token::BorrowedStr("/"),
                Token::Struct { name: "cid", len: 3, },
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
                Token::TupleVariantEnd,
            ],
        );
    }

    #[test]
    fn test_script_cidv1_json() {
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

        let t = Script::Cid(Key::default(), v1);
        let s = serde_json::to_string(&t).unwrap();
        assert_eq!(s,
            "{\"cid\":[\"/\",{\"version\":1,\"encoding\":\"dag-cbor\",\"hash\":{\"codec\":\"sha3-512\",\"hash\":\"f405792dad96085b6076b8e4e63b578c90d0336bcaadef4f24704df866149526a1e6d23f89e218ad3f6172a7e26e6e37a3dea728e5f232e41696ad286bcca9201be\"}}]}"
        );
        assert_eq!(t, serde_json::from_str(&s).unwrap());
    }

    #[test]
    fn test_script_cidv1_cbor() {
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

        let s = Script::Cid(Key::default(), v1);
        let b = serde_cbor::to_vec(&s).unwrap();
        assert_eq!(b, vec![88, 73, 138, 36, 2, 1, 47, 1, 113, 20, 64, 87, 146, 218, 217, 96, 133, 182, 7, 107, 142, 78, 99, 181, 120, 201, 13, 3, 54, 188, 170, 222, 244, 242, 71, 4, 223, 134, 97, 73, 82, 106, 30, 109, 35, 248, 158, 33, 138, 211, 246, 23, 42, 126, 38, 230, 227, 122, 61, 234, 114, 142, 95, 35, 46, 65, 105, 106, 210, 134, 188, 202, 146, 1, 190]);
        assert_eq!(s, serde_cbor::from_slice(b.as_slice()).unwrap());
    }

    #[test]
    fn test_preimage_entry_serde_compact() {
        // build a nonce
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

        let script = Script::Cid(Key::default(), cid);
        let op = Op::Update("/move".try_into().unwrap(), Value::Str("zig!".into()));
        let entry = entry::Builder::default()
            .with_vlad(&vlad)
            .add_lock(&script)
            .with_unlock(&script)
            .add_op(&op)
            .try_build(|e| {
                Ok(e.vlad.clone().into())
            })
            .unwrap();

        /*
        let v: Vec<u8> = entry.clone().into();
        print!("BLAH: ");
        for b in &v {
            print!("0x{:02x}, ", b);
        }
        println!("");
        */

        assert_tokens(
            &entry.compact(),
            &[
                Token::BorrowedBytes(&[137, 36, 1, 135, 36, 187, 36, 32, 209, 92, 79, 178, 145, 26, 225, 51, 127, 16, 43, 202, 244, 192, 8, 141, 54, 52, 91, 136, 178, 67, 150, 142, 131, 76, 95, 250, 23, 144, 120, 50, 1, 113, 20, 64, 87, 146, 218, 217, 96, 133, 182, 7, 107, 142, 78, 99, 181, 120, 201, 13, 3, 54, 188, 170, 222, 244, 242, 71, 4, 223, 134, 97, 73, 82, 106, 30, 109, 35, 248, 158, 33, 138, 211, 246, 23, 42, 126, 38, 230, 227, 122, 61, 234, 114, 142, 95, 35, 46, 65, 105, 106, 210, 134, 188, 202, 146, 1, 190, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 2, 5, 47, 109, 111, 118, 101, 1, 4, 122, 105, 103, 33, 1, 138, 36, 2, 1, 47, 1, 113, 20, 64, 87, 146, 218, 217, 96, 133, 182, 7, 107, 142, 78, 99, 181, 120, 201, 13, 3, 54, 188, 170, 222, 244, 242, 71, 4, 223, 134, 97, 73, 82, 106, 30, 109, 35, 248, 158, 33, 138, 211, 246, 23, 42, 126, 38, 230, 227, 122, 61, 234, 114, 142, 95, 35, 46, 65, 105, 106, 210, 134, 188, 202, 146, 1, 190, 138, 36, 2, 1, 47, 1, 113, 20, 64, 87, 146, 218, 217, 96, 133, 182, 7, 107, 142, 78, 99, 181, 120, 201, 13, 3, 54, 188, 170, 222, 244, 242, 71, 4, 223, 134, 97, 73, 82, 106, 30, 109, 35, 248, 158, 33, 138, 211, 246, 23, 42, 126, 38, 230, 227, 122, 61, 234, 114, 142, 95, 35, 46, 65, 105, 106, 210, 134, 188, 202, 146, 1, 190, 105, 135, 36, 187, 36, 32, 209, 92, 79, 178, 145, 26, 225, 51, 127, 16, 43, 202, 244, 192, 8, 141, 54, 52, 91, 136, 178, 67, 150, 142, 131, 76, 95, 250, 23, 144, 120, 50, 1, 113, 20, 64, 87, 146, 218, 217, 96, 133, 182, 7, 107, 142, 78, 99, 181, 120, 201, 13, 3, 54, 188, 170, 222, 244, 242, 71, 4, 223, 134, 97, 73, 82, 106, 30, 109, 35, 248, 158, 33, 138, 211, 246, 23, 42, 126, 38, 230, 227, 122, 61, 234, 114, 142, 95, 35, 46, 65, 105, 106, 210, 134, 188, 202, 146, 1, 190]),
            ],
        );
    }
}
