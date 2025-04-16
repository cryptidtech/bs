// SPDX-License-Idnetifier: Apache-2.0
//! Serde (de)serialization for ['crate::prelude::Tagged'] wrapped objects
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use serde::{Deserialize, Serialize};
    use serde_test::{assert_tokens, Configure, Token};

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    struct Unit((u8, [u8; 2]));

    type EncodedUnit = BaseEncoded<Unit>;

    impl Unit {
        fn encoded_default() -> EncodedUnit {
            EncodedUnit::new(Unit::preferred_encoding(), Unit::default())
        }
    }

    impl Default for Unit {
        fn default() -> Self {
            Self((0x59, [0xDE, 0xAD]))
        }
    }

    impl EncodingInfo for Unit {
        fn preferred_encoding() -> Base {
            Base::Base16Lower
        }

        fn encoding(&self) -> Base {
            Self::preferred_encoding()
        }
    }

    impl<'a> TryFrom<&'a [u8]> for Unit {
        type Error = Error;

        fn try_from(s: &'a [u8]) -> Result<Self, Error> {
            if s.len() < 3 {
                Err(Error::custom("too few items in the vec"))
            } else {
                Ok(Self((s[0], [s[1], s[2]])))
            }
        }
    }

    impl Into<Vec<u8>> for Unit {
        fn into(self) -> Vec<u8> {
            let mut v: Vec<u8> = Vec::default();
            v.push(self.0 .0);
            v.extend_from_slice(&self.0 .1);
            v
        }
    }

    #[test]
    fn test_serde_base_encoded_readable() {
        let unit = Unit::encoded_default();
        assert_tokens(&unit.readable(), &[Token::BorrowedStr("f59dead")]);
    }

    #[test]
    fn test_serde_base_encoded_compact() {
        let unit = Unit::encoded_default();
        assert_tokens(
            &unit.compact(),
            &[
                Token::Tuple { len: 2 },
                Token::Char('f'),
                Token::NewtypeStruct { name: "Unit" },
                Token::Tuple { len: 2 },
                Token::U8(0x59),
                Token::Tuple { len: 2 },
                Token::U8(0xDE),
                Token::U8(0xAD),
                Token::TupleEnd,
                Token::TupleEnd,
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_cbor_reader_writer() {
        let unit1 = Unit::default();
        let mut b = Vec::new();
        serde_cbor::to_writer(&mut b, &unit1).unwrap();
        let unit2: Unit = serde_cbor::from_reader(b.as_slice()).unwrap();
        assert_eq!(unit1, unit2);
    }

    #[test]
    fn test_json_reader_writer() {
        let unit1 = Unit::default();
        let mut b = Vec::new();
        serde_json::to_writer_pretty(&mut b, &unit1).unwrap();
        let unit2: Unit = serde_json::from_reader(b.as_slice()).unwrap();
        assert_eq!(unit1, unit2);
    }

    #[test]
    fn test_encoded_cbor_reader_writer() {
        let unit1 = Unit::encoded_default();
        let mut b = Vec::new();
        serde_cbor::to_writer(&mut b, &unit1).unwrap();
        let unit2: EncodedUnit = serde_cbor::from_reader(b.as_slice()).unwrap();
        assert_eq!(unit1, unit2);
    }

    #[test]
    fn test_encoded_json_reader_writer() {
        let unit1 = Unit::encoded_default();
        let mut b = Vec::new();
        serde_json::to_writer_pretty(&mut b, &unit1).unwrap();
        let unit2: EncodedUnit = serde_json::from_reader(b.as_slice()).unwrap();
        assert_eq!(unit1, unit2);
    }

    #[test]
    fn test_serde_json() {
        let unit = Unit::encoded_default();
        let unit_s = serde_json::to_string(&unit).unwrap();
        assert_eq!(unit_s, "\"f59dead\"".to_string());
    }

    #[test]
    fn test_serde_cbor() {
        let unit = Unit::encoded_default();
        let unit_cbor = serde_cbor::to_vec(&unit).unwrap();
        assert_eq!(unit_cbor, hex::decode("8261668218598218de18ad").unwrap());
    }

    #[test]
    fn test_u8_varuint() {
        let v = Varuint(0x01_u8);
        assert_tokens(&v, &[Token::BorrowedBytes(&[0x01])])
    }

    #[test]
    fn test_u8_long_varuint() {
        let v = Varuint(0xFF_u8);
        assert_tokens(&v, &[Token::BorrowedBytes(&[0xFF, 0x01])])
    }

    #[test]
    fn test_u16_varuint() {
        let v = Varuint(0x0100_u16);
        assert_tokens(&v, &[Token::BorrowedBytes(&[0x80, 0x02])])
    }

    #[test]
    fn test_u16_short_varuint() {
        let v = Varuint(0x0001_u16);
        assert_tokens(&v, &[Token::BorrowedBytes(&[0x01])])
    }

    #[test]
    fn test_u16_long_varuint() {
        let v = Varuint(0xFFFF_u16);
        assert_tokens(&v, &[Token::BorrowedBytes(&[0xFF, 0xFF, 0x03])])
    }

    #[test]
    fn test_u32_varuint() {
        let v = Varuint(0x0100_0000_u32);
        assert_tokens(&v, &[Token::BorrowedBytes(&[0x80, 0x80, 0x80, 0x08])])
    }

    #[test]
    fn test_u32_short_varuint() {
        let v = Varuint(0x0000_0001_u32);
        assert_tokens(&v, &[Token::BorrowedBytes(&[0x01])])
    }

    #[test]
    fn test_u32_long_varuint() {
        let v = Varuint(0xFFFF_FFFF_u32);
        assert_tokens(&v, &[Token::BorrowedBytes(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F])])
    }

    #[test]
    fn test_u64_varuint() {
        let v = Varuint(0x0100_0000_0000_0000_u64);
        assert_tokens(
            &v,
            &[Token::BorrowedBytes(&[
                0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
            ])],
        )
    }

    #[test]
    fn test_u64_short_varuint() {
        let v = Varuint(0x0000_0000_0000_0001_u64);
        assert_tokens(&v, &[Token::BorrowedBytes(&[0x01])])
    }

    #[test]
    fn test_u64_long_varuint() {
        let v = Varuint(0xFFFF_FFFF_FFFF_FFFF_u64);
        assert_tokens(
            &v,
            &[Token::BorrowedBytes(&[
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
            ])],
        )
    }

    #[test]
    fn test_u128_varuint() {
        let v = Varuint(0x0100_0000_0000_0000_0000_0000_0000_0000_u128);
        assert_tokens(
            &v,
            &[Token::Bytes(&[
                0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                0x80, 0x80, 0x80, 0x02,
            ])],
        )
    }

    #[test]
    fn test_u128_short_varuint() {
        let v = Varuint(0x0000_0000_0000_0000_0000_0000_0000_0001_u128);
        assert_tokens(&v, &[Token::Bytes(&[0x01])])
    }

    #[test]
    fn test_u128_long_varuint() {
        let v = Varuint(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_u128);
        assert_tokens(
            &v,
            &[Token::Bytes(&[
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0x03,
            ])],
        )
    }

    #[test]
    fn test_usize_varuint() {
        let v = Varuint(0x0100_0000_0000_0000_usize);
        assert_tokens(
            &v,
            &[Token::Bytes(&[
                0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
            ])],
        )
    }

    #[test]
    fn test_usize_short_varuint() {
        let v = Varuint(0x0000_0000_0000_0001_usize);
        assert_tokens(&v, &[Token::Bytes(&[0x01])])
    }

    #[test]
    fn test_usize_long_varuint() {
        let v = Varuint(0xFFFF_FFFF_FFFF_FFFF_usize);
        assert_tokens(
            &v,
            &[Token::Bytes(&[
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
            ])],
        )
    }

    #[test]
    fn test_usize_encoded() {
        let v = Varuint::encoded_new(Base::Base16Lower, 0x0100_0000_0000_0000_usize);
        assert_tokens(&v.readable(), &[Token::Str("f808080808080808001")]);
    }

    #[test]
    fn test_varbytes() {
        let v = Varbytes(vec![0x01, 0x02, 0x03]);
        assert_tokens(&v, &[Token::Bytes(&[0x03, 0x01, 0x02, 0x03])]);
    }

    #[test]
    fn test_encoded_varbytes() {
        let v = Varbytes::encoded_new(Base::Base16Lower, vec![0x01, 0x02, 0x03]);
        assert_tokens(&v.readable(), &[Token::Str("f03010203")]);
    }
}
