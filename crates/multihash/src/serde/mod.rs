// SPDX-License-Idnetifier: Apache-2.0
//! Serde (de)serialization for [`crate::Multihash`]
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::prelude::{Base, Builder, Codec, Multihash};
    use multitrait::Null;
    use serde_test::{assert_tokens, Configure, Token};

    #[test]
    fn test_serde_compact() {
        let mh = Builder::new_from_bytes(Codec::Blake2S256, b"for great justice, move every zig!")
            .unwrap()
            .try_build()
            .unwrap();

        assert_tokens(
            &mh.compact(), // convert to Tagged<MultihashImpl>
            &[
                Token::BorrowedBytes(&[0xE0, 0xE4, 0x02, // Codec::Blake2S256 as varuint
                    0x20, 0x64, 0x22, 0x03, 0x12, 0x5d, 0x59, 0xe8,
                    0xb9, 0x3e, 0xdb, 0x67, 0x6f, 0xc7, 0x8d, 0xe9, 
                    0xc5, 0x87, 0xcf, 0x52, 0xcc, 0xc6, 0xf2, 0x19,
                    0x03, 0x2d, 0xa1, 0xf3, 0x77, 0x08, 0x23, 0x32, 0xb0,
                ]),
            ],
        );
    }

    #[test]
    fn test_serde_encoded_string() {
        let mh = Builder::new_from_bytes(Codec::Blake2S256, b"for great justice, move every zig!")
            .unwrap()
            .with_base_encoding(Base::Base58Btc)
            .try_build_encoded()
            .unwrap();

        assert_tokens(
            &mh.readable(),
            &[Token::BorrowedStr(
                "z2i3XjxBTdEn8wccxPbpSQgKveXi5jB8zUn4S9u57ZmyhQuS3bm",
            )],
        );
    }

    #[test]
    fn test_serde_string() {
        let mh = Builder::new_from_bytes(Codec::Blake2S256, b"for great justice, move every zig!")
            .unwrap()
            .try_build()
            .unwrap();
        assert_tokens(
            &mh.readable(),
            &[
                Token::Struct {
                    name: "multihash",
                    len: 2,
                },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("blake2s-256"),
                Token::BorrowedStr("hash"),
                Token::BorrowedStr(
                    "f20642203125d59e8b93edb676fc78de9c587cf52ccc6f219032da1f377082332b0",
                ),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_serde_json() {
        let mh1 = Builder::new_from_bytes(Codec::Blake2S256, b"for great justice, move every zig!")
            .unwrap()
            .try_build()
            .unwrap();
        let s = serde_json::to_string(&mh1).unwrap();
        assert_eq!(s, "{\"codec\":\"blake2s-256\",\"hash\":\"f20642203125d59e8b93edb676fc78de9c587cf52ccc6f219032da1f377082332b0\"}".to_string());
        let mh2: Multihash = serde_json::from_str(&s).unwrap();
        assert_eq!(mh1, mh2);
    }

    #[test]
    fn test_serde_cbor() {
        let mh1 = Builder::new_from_bytes(Codec::Blake2S256, b"for great justice, move every zig!")
            .unwrap()
            .try_build()
            .unwrap();
        let v = serde_cbor::to_vec(&mh1).unwrap();
        //println!("serde_cbor: {}", hex::encode(&v));
        assert_eq!(v, hex::decode("5824e0e40220642203125d59e8b93edb676fc78de9c587cf52ccc6f219032da1f377082332b0").unwrap());
        let mh2: Multihash = serde_cbor::from_slice(&v).unwrap();
        assert_eq!(mh1, mh2);
    }

    #[test]
    fn test_null_serde_compact() {
        let mh = Multihash::null();
        assert_tokens(
            &mh.compact(),
            &[
                // 0x00 is Codec::identity
                // 0x00 is digest length
                Token::BorrowedBytes(&[0x00, 0x00]),
            ],
        );
    }

    #[test]
    fn test_null_serde_readable() {
        let mh = Multihash::null();
        assert_tokens(
            &mh.readable(),
            &[
                Token::Struct { name: "multihash", len: 2 },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("identity"),
                Token::BorrowedStr("hash"),
                Token::BorrowedStr("f00"),
                Token::StructEnd,
            ],
        );
    }
}
