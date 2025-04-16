// SPDX-License-Idnetifier: Apache-2.0
//! Serde (de)serialization for [`crate::Multikey`].
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::{cipher, kdf, nonce, Builder, EncodedMultikey, Multikey, Views};
    use multibase::Base;
    use multicodec::Codec;
    use multihash::EncodedMultihash;
    use multitrait::Null;
    use multiutil::BaseEncoded;
    use serde::{Deserialize, Serialize};
    use serde_test::{assert_tokens, Configure, Token};
    use std::collections::BTreeMap;

    #[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
    struct Wrapper {
        pub map: BTreeMap<EncodedMultihash, Multikey>,
    }

    #[test]
    fn test_serde_macros() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let sk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();
        let skh = {
            let fv = sk.fingerprint_view().unwrap();
            EncodedMultihash::new(Base::Base58Btc, fv.fingerprint(Codec::Blake2S256).unwrap())
        };
        let pk = {
            let cv = sk.conv_view().unwrap();
            cv.to_public_key().unwrap()
        };
        let pkh = {
            let fv = sk.fingerprint_view().unwrap();
            EncodedMultihash::new(Base::Base58Btc, fv.fingerprint(Codec::Blake2S256).unwrap())
        };

        let mut w1 = Wrapper::default();
        w1.map.insert(skh, sk);
        w1.map.insert(pkh, pk);

        let b = serde_cbor::to_vec(&w1).unwrap();
        let w2 = serde_cbor::from_slice(b.as_slice()).unwrap();
        assert_eq!(w1, w2);
        let s = serde_json::to_string(&w1).unwrap();
        let w3 = serde_json::from_str(&s).unwrap();
        assert_eq!(w1, w3);
    }

    #[test]
    fn test_serde_compact() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let sk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        // try to get the associated public key
        let mk = {
            let conv = sk.conv_view().unwrap();
            
            conv.to_public_key().unwrap()
        };

        //let v: Vec<u8> = mk.clone().into();
        //println!("public key: {}", hex::encode(&v));

        assert_tokens(
            &mk.compact(),
            &[Token::BorrowedBytes(&[
                0xba, 0x24, // Multikey sigil
                0xed, 0x01, // Ed25519 public key as varuint
                0x08, // comment length
                0x74, 0x65, 0x73, 0x74, 0x20, 0x6b, 0x65, 0x79, // comment
                0x01, // 1 attribute
                0x01, // key data attributes
                0x20, // 32 bytes in the public key
                // public key bytes
                0x13, 0xe1, 0xe6, 0xe8, 0xc3, 0x53, 0x67, 0x2b, 0x75, 0x9c, 0x93, 0xc3, 0x97, 0x95,
                0x69, 0x27, 0xe1, 0x50, 0x3c, 0x6e, 0xdd, 0x73, 0xf2, 0x40, 0xcc, 0xff, 0x2b, 0x7d,
                0xd0, 0x45, 0x58, 0xb6,
            ])],
        );
    }

    #[test]
    fn test_serde_encoded_string() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let pk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .with_base_encoding(Base::Base58Btc)
            .try_build_encoded()
            .unwrap();

        assert_tokens(
            &pk.readable(),
            &[Token::Str(
                "z7q2yVpRpajoAeCS88yKcpYdNB5dtDEDvKqPGXAyTEebE8qxx8Zgh8MwFcbbvbMTSjT",
            )],
        );
    }

    #[test]
    fn test_serde_readable() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let sk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        let mk = {
            let conv = sk.conv_view().unwrap();
            
            conv.to_public_key().unwrap()
        };

        assert_tokens(
            &mk.readable(),
            &[
                Token::Struct {
                    name: "multikey",
                    len: 3,
                },
                Token::Str("codec"),
                Token::Str("ed25519-pub"),
                Token::Str("comment"),
                Token::Str("test key"),
                Token::Str("attributes"),
                Token::Seq { len: Some(1) },
                Token::Tuple { len: 2 },
                Token::Str("key-data"), // AttrId::KeyData
                Token::Str("f2013e1e6e8c353672b759c93c397956927e1503c6edd73f240ccff2b7dd04558b6"),
                Token::TupleEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_serde_encrypted_secret_key_compact() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let mk1 = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        let attr = mk1.attr_view().unwrap();
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk1.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());

        let mk2 = {
            let salt =
                hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406")
                    .unwrap();
            let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
                .with_salt(&salt)
                .with_rounds(10)
                .try_build()
                .unwrap();

            let nonce = hex::decode("714e5abf0f7beae8aabbccdd").unwrap();
            let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
                .with_nonce(&nonce)
                .try_build()
                .unwrap();

            // get the kdf view
            let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .derive_key(b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = mk1.cipher_view(&ciphermk).unwrap();
            // encrypt the multikey using the cipher
            cipher.encrypt().unwrap()
        };

        /*
                let v: Vec<u8> = mk2.clone().into();
                print!("mk2: ");
                for b in &v {
                    print!("0x{:02x}, ", b);
                }
                println!("");
        */

        assert_tokens(
            &mk2.compact(),
            &[Token::BorrowedBytes(&[
                0xba, 0x24, // Multikey sigil
                0x80, 0x26, // Ed25519 private codec as varuint
                0x08, // comment of 8 bytes
                // comment
                0x74, 0x65, 0x73, 0x74, 0x20, 0x6b, 0x65, 0x79, 0x08, // 8 bytes of attributes
                // key is encrypted
                0x00, 0x01, 0x01, // 3 bytes
                // key data of 32 bytes
                0x01, 0x20, // 0x20 = 32 byte key
                0xef, 0x7c, 0xf7, 0x8f, 0x3e, 0x0e, 0x58, 0x82, // 8 bytes
                0x32, 0xa4, 0x23, 0xdb, 0x1f, 0xdf, 0x02, 0xe2, // 16 bytes
                0x18, 0xc4, 0x94, 0x4c, 0x35, 0xba, 0x4e, 0xb4, // 24 bytes
                0x54, 0x96, 0xb5, 0x27, 0x42, 0x53, 0x9d, 0x78, // 32 bytes
                // cipher codec
                0x02, 0x02, 0xa5, 0x01, // codec (Chacha20Poly1305)
                // cipher key len (32)
                0x03, 0x01, 0x20, // 3 bytes codec
                // 12 byte cipher nonce
                0x04, 0x0c, // 0x0c = 12 bytes of nonce
                0x71, 0x4e, 0x5a, 0xbf, 0x0f, // 6 bytes
                0x7b, 0xea, 0xe8, 0xaa, 0xbb, 0xcc, 0xdd, // 12 bytes
                // kdf codec
                0x05, 0x03, 0x8d, 0xa0, 0x03, // kdf salt
                0x06, 0x20, // 2 bytes salt codec
                0x62, 0x1f, 0x20, 0xcf, 0xda, 0x14, 0x0b, 0xd8, // 8 bytes salt
                0xbf, 0x83, 0xa8, 0x99, 0x16, 0x74, 0x28, 0x46, // 16
                0x29, 0x29, 0xa4, 0x1e, 0x9b, 0x68, 0xa8, 0x46, // 24
                0x7b, 0xfc, 0x24, 0x55, 0xe9, 0xf9, 0x84, 0x06, // 32
                // kdf rounds (10)
                0x07, 0x01, 0x0a, // 3 bytes rounds
            ])],
        );
    }

    #[test]
    fn test_serde_encrypted_secret_key_readable() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let mk1 = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        let attr = mk1.attr_view().unwrap();
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk1.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());

        let mk2 = {
            let salt =
                hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406")
                    .unwrap();
            let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
                .with_salt(&salt)
                .with_rounds(10)
                .try_build()
                .unwrap();
            let nonce = hex::decode("714e5abf0f7beae8aabbccdd").unwrap();
            let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
                .with_nonce(&nonce)
                .try_build()
                .unwrap();

            // get the kdf view
            let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .derive_key(b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = mk1.cipher_view(&ciphermk).unwrap();
            // encrypt the multikey using the cipher
            cipher.encrypt().unwrap()
        };

        assert_tokens(
            &mk2.readable(),
            &[
                Token::Struct {
                    name: "multikey",
                    len: 3,
                },
                Token::Str("codec"),
                Token::Str("ed25519-priv"),
                Token::Str("comment"),
                Token::Str("test key"),
                Token::Str("attributes"),
                Token::Seq { len: Some(8) },
                Token::Tuple { len: 2 },
                Token::Str("key-is-encrypted"),
                Token::Str("f0101"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::Str("key-data"),
                Token::Str("f20ef7cf78f3e0e588232a423db1fdf02e218c4944c35ba4eb45496b52742539d78"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::Str("cipher-codec"),
                Token::Str("f02a501"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::Str("cipher-key-len"),
                Token::Str("f0120"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::Str("cipher-nonce"),
                Token::Str("f0c714e5abf0f7beae8aabbccdd"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::Str("kdf-codec"),
                Token::Str("f038da003"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::Str("kdf-salt"),
                Token::Str("f20621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::Str("kdf-rounds"),
                Token::Str("f010a"),
                Token::TupleEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_serde_encrypted_secret_key_json() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let mk1 = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        let attr = mk1.attr_view().unwrap();
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk1.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());

        let mk2 = {
            let salt =
                hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406")
                    .unwrap();
            let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
                .with_salt(&salt)
                .with_rounds(10)
                .try_build()
                .unwrap();

            let nonce = hex::decode("714e5abf0f7beae8aabbccdd").unwrap();
            let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
                .with_nonce(&nonce)
                .try_build()
                .unwrap();

            // get the kdf view
            let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .derive_key(b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = mk1.cipher_view(&ciphermk).unwrap();
            // encrypt the multikey using the cipher
            cipher.encrypt().unwrap()
        };

        let s = serde_json::to_string(&mk2).unwrap();
        assert_eq!(s, "{\"codec\":\"ed25519-priv\",\"comment\":\"test key\",\"attributes\":[[\"key-is-encrypted\",\"f0101\"],[\"key-data\",\"f20ef7cf78f3e0e588232a423db1fdf02e218c4944c35ba4eb45496b52742539d78\"],[\"cipher-codec\",\"f02a501\"],[\"cipher-key-len\",\"f0120\"],[\"cipher-nonce\",\"f0c714e5abf0f7beae8aabbccdd\"],[\"kdf-codec\",\"f038da003\"],[\"kdf-salt\",\"f20621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406\"],[\"kdf-rounds\",\"f010a\"]]}".to_string());

        let mk3: Multikey = serde_json::from_str(&s).unwrap();
        assert_eq!(mk2, mk3);
    }

    #[test]
    fn test_serde_encrypted_bls_secret_key_share_json() {
        /*
        let bytes = hex::decode("4b79b6a7da7cdc9fe17e368450f08ae5a5f42347f4863f2ee23404f99aa62147")
            .unwrap();
        let emk = Builder::new(Codec::Bls12381G1Priv)
            .with_comment("test key")
            .with_base_encoding(Base::Base58Btc)
            .with_key_bytes(&bytes)
            .try_build_encoded()
            .unwrap();
        println!("encoded bls private: {}", emk);
        */

        // build a secret key share multikey
        let emk = EncodedMultikey::try_from(
            "z7q2zUpseNi9mxc7jQjYD1aUdcdaAFPMenhrwDvLXotf6NJYJdNfz4zjSADxfEhSWjg",
        )
        .unwrap();
        let mk1 = emk.to_inner();

        let attr = mk1.attr_view().unwrap();
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk1.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());

        let mk2 = {
            let salt =
                hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406")
                    .unwrap();
            let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
                .with_salt(&salt)
                .with_rounds(10)
                .try_build()
                .unwrap();

            let nonce = hex::decode("714e5abf0f7beae8aabbccdd").unwrap();
            let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
                .with_nonce(&nonce)
                .try_build()
                .unwrap();

            // get the kdf view
            let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .derive_key(b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = mk1.cipher_view(&ciphermk).unwrap();
            // encrypt the multikey using the cipher
            cipher.encrypt().unwrap()
        };

        let s = serde_json::to_string(&mk2).unwrap();
        println!("{}", s);
        assert_eq!(s, "{\"codec\":\"bls12_381-g1-priv\",\"comment\":\"test key\",\"attributes\":[[\"key-is-encrypted\",\"f0101\"],[\"key-data\",\"f20da4d0758cd8d3debfbf143b6813c94ed6bd40a0ddb0971f3caf51daeec3a3acd\"],[\"cipher-codec\",\"f02a501\"],[\"cipher-key-len\",\"f0120\"],[\"cipher-nonce\",\"f0c714e5abf0f7beae8aabbccdd\"],[\"kdf-codec\",\"f038da003\"],[\"kdf-salt\",\"f20621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406\"],[\"kdf-rounds\",\"f010a\"]]}".to_string());

        let mk3: Multikey = serde_json::from_str(&s).unwrap();
        assert_eq!(mk2, mk3);
    }

    #[test]
    fn test_encoded_public_key() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let sk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        // try to get the associated public key
        let pk = {
            let conv = sk.conv_view().unwrap();
            conv.to_public_key().unwrap()
        };

        // try to get the associated public key
        let mk1 = BaseEncoded::new(Base::Base58Btc, pk);
        let mk2 = EncodedMultikey::try_from(mk1.to_string().as_str()).unwrap();

        assert_eq!(mk1, mk2);
    }

    #[test]
    fn test_nonce_serde_compact() {
        let bytes = hex::decode("76895272c5ce5c0c72b5ec54944ead739482f87048dbbfc13b873008b31d5995")
            .unwrap();
        let n = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

        assert_tokens(
            &n.compact(),
            &[Token::BorrowedBytes(&[
                187, 36, 32, 118, 137, 82, 114, 197, 206, 92, 12, 114, 181, 236, 84, 148, 78, 173,
                115, 148, 130, 248, 112, 72, 219, 191, 193, 59, 135, 48, 8, 179, 29, 89, 149,
            ])],
        );
    }

    #[test]
    fn test_nonce_serde_encoded_string() {
        let bytes = hex::decode("76895272c5ce5c0c72b5ec54944ead739482f87048dbbfc13b873008b31d5995")
            .unwrap();
        let n = nonce::Builder::new_from_bytes(&bytes)
            .try_build_encoded()
            .unwrap();

        assert_tokens(
            &n.readable(),
            &[Token::Str(
                "fbb242076895272c5ce5c0c72b5ec54944ead739482f87048dbbfc13b873008b31d5995",
            )],
        );
    }

    #[test]
    fn test_nonce_serde_readable() {
        let bytes = hex::decode("76895272c5ce5c0c72b5ec54944ead739482f87048dbbfc13b873008b31d5995")
            .unwrap();
        let n = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

        assert_tokens(
            &n.readable(),
            &[
                Token::Struct {
                    name: "nonce",
                    len: 1,
                },
                Token::Str("nonce"),
                Token::Str("f2076895272c5ce5c0c72b5ec54944ead739482f87048dbbfc13b873008b31d5995"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_null_multikey_serde_compact() {
        let mk = Multikey::null();
        assert_tokens(&mk.compact(), &[Token::BorrowedBytes(&[186, 36, 0, 0, 0])]);
    }

    #[test]
    fn test_null_multikey_serde_readable() {
        let mk = Multikey::null();
        assert_tokens(
            &mk.readable(),
            &[
                Token::Struct {
                    name: "multikey",
                    len: 3,
                },
                Token::Str("codec"),
                Token::Str("identity"),
                Token::Str("comment"),
                Token::Str(""),
                Token::Str("attributes"),
                Token::Seq { len: Some(0) },
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_encoded_null_multikey_serde_readable() {
        let mk: EncodedMultikey = Multikey::null().into();
        assert_tokens(&mk.readable(), &[Token::Str("fba24000000")]);
    }

    #[test]
    fn test_null_nonce_serde_compact() {
        let n = nonce::Nonce::null();
        assert_tokens(&n.compact(), &[Token::BorrowedBytes(&[187, 36, 0])]);
    }

    #[test]
    fn test_null_nonce_serde_readable() {
        let n = nonce::Nonce::null();
        assert_tokens(
            &n.readable(),
            &[
                Token::Struct {
                    name: "nonce",
                    len: 1,
                },
                Token::Str("nonce"),
                Token::Str("f00"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_encoded_null_nonce_serde_readable() {
        let n: nonce::EncodedNonce = nonce::Nonce::null().into();
        assert_tokens(&n.readable(), &[Token::Str("fbb2400")]);
    }
}
