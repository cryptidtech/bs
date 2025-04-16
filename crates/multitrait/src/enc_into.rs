// SPDX-License-Idnetifier: Apache-2.0
use unsigned_varint::{decode, encode};

/// This trait encodes a numeric value into a compact varuint Vec<u8>
pub trait EncodeInto {
    /// encode the type into a compact varuint Vec<u8>
    fn encode_into(&self) -> Vec<u8>;
}

/// Encode a bool into a compact varuint Vec<u8>
impl EncodeInto for bool {
    fn encode_into(&self) -> Vec<u8> {
        match *self {
            true => vec![1u8],
            false => vec![0u8],
        }
    }
}

/// Encode a u8 into a compact varuint Vec<u8>
impl EncodeInto for u8 {
    fn encode_into(&self) -> Vec<u8> {
        let mut buf = encode::u8_buffer();
        encode::u8(*self, &mut buf);
        let mut v: Vec<u8> = Vec::new();
        for b in buf {
            v.push(b);
            if decode::is_last(b) {
                break;
            }
        }
        v
    }
}

/// Encode a u16 into a compact varuint Vec<u8>
impl EncodeInto for u16 {
    fn encode_into(&self) -> Vec<u8> {
        let mut buf = encode::u16_buffer();
        encode::u16(*self, &mut buf);
        let mut v: Vec<u8> = Vec::new();
        for b in buf {
            v.push(b);
            if decode::is_last(b) {
                break;
            }
        }
        v
    }
}

/// Encode a u32 into a compact varuint Vec<u8>
impl EncodeInto for u32 {
    fn encode_into(&self) -> Vec<u8> {
        let mut buf = encode::u32_buffer();
        encode::u32(*self, &mut buf);
        let mut v: Vec<u8> = Vec::new();
        for b in buf {
            v.push(b);
            if decode::is_last(b) {
                break;
            }
        }
        v
    }
}

/// Encode a u64 into a compact varuint Vec<u8>
impl EncodeInto for u64 {
    fn encode_into(&self) -> Vec<u8> {
        let mut buf = encode::u64_buffer();
        encode::u64(*self, &mut buf);
        let mut v: Vec<u8> = Vec::new();
        for b in buf {
            v.push(b);
            if decode::is_last(b) {
                break;
            }
        }
        v
    }
}

/// Encode a u128 into a compact varuint Vec<u8>
impl EncodeInto for u128 {
    fn encode_into(&self) -> Vec<u8> {
        let mut buf = encode::u128_buffer();
        encode::u128(*self, &mut buf);
        let mut v: Vec<u8> = Vec::new();
        for b in buf {
            v.push(b);
            if decode::is_last(b) {
                break;
            }
        }
        v
    }
}

/// Encode a usize into a compact varuint Vec<u8>
impl EncodeInto for usize {
    fn encode_into(&self) -> Vec<u8> {
        let mut buf = encode::usize_buffer();
        encode::usize(*self, &mut buf);
        let mut v: Vec<u8> = Vec::new();
        for b in buf {
            v.push(b);
            if decode::is_last(b) {
                break;
            }
        }
        v
    }
}
