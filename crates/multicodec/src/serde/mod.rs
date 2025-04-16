// SPDX-License-Identifier: MIT or Apache-2.0
//! Serde (de)serialization for [`crate::prelude::Codec`]
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::prelude::Codec;
    use multitrait::Null;
    use serde::{Deserialize, Serialize};
    use serde_test::{assert_tokens, Configure, Token};

    #[test]
    fn test_serde_binary() {
        let c = Codec::Ed25519Pub;
        assert_tokens(&c.compact(), &[Token::BorrowedBytes(&[0xED, 0x01])])
    }

    #[test]
    fn test_serde_readable() {
        let c = Codec::Ed25519Pub;
        assert_tokens(&c.readable(), &[Token::BorrowedStr("ed25519-pub")])
    }

    #[test]
    fn test_null_serde_compact() {
        let c = Codec::null();
        assert_tokens(
            &c.compact(),
            &[
                Token::BorrowedBytes(&[0x00])
            ]
        );
    }

    #[test]
    fn test_null_serde_readable() {
        let c = Codec::null();
        assert_tokens(
            &c.readable(),
            &[
                Token::BorrowedStr("identity")
            ]
        );
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    struct Wrapper {
        v: Codec,
    }

    #[test]
    fn test_serde_macros() {
        let w1 = Wrapper {
            v: Codec::Ed25519Pub,
        };
        let b = serde_cbor::to_vec(&w1).unwrap();
        let w2 = serde_cbor::from_slice(b.as_slice()).unwrap();
        assert_eq!(w1, w2);
        let s = serde_json::to_string_pretty(&w1).unwrap();
        println!("{}", s);
        let w3 = serde_json::from_str(&s).unwrap();
        assert_eq!(w1, w3);
    }

    #[test]
    fn test_cbor_reader_writer() {
        let w1 = Wrapper {
            v: Codec::Ed25519Pub,
        };

        let mut b: Vec<u8> = Vec::new();
        serde_cbor::to_writer(&mut b, &w1).unwrap();
        let w2: Wrapper = serde_cbor::from_reader(b.as_slice()).unwrap();
        assert_eq!(w1, w2);
    }

    #[test]
    fn test_json_reader_writer() {
        let w1 = Wrapper {
            v: Codec::Ed25519Pub,
        };

        let mut b: Vec<u8> = Vec::new();
        serde_json::to_writer(&mut b, &w1).unwrap();
        let w2: Wrapper = serde_json::from_reader(b.as_slice()).unwrap();
        assert_eq!(w1, w2);
    }
}
