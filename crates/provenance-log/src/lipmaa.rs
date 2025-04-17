// SPDX-License-Identifier: FSL-1.1
/// Trait for calculating Lipmaa numbers for unsigned integers
pub trait Lipmaa {
    /// Tests if this is a number with a long lipmaa backlink
    fn is_lipmaa(&self) -> bool;
    /// Returns the lipmaa number
    fn lipmaa(&self) -> Self;
    /// Returns the greatest number in this number's certificate set
    fn node_z(&self) -> Self;
}

impl Lipmaa for u64 {
    fn is_lipmaa(&self) -> bool {
        if *self == 0 {
            return false;
        }
        self.lipmaa() + 1 != *self
    }

    fn lipmaa(&self) -> Self {
        if *self == 0 {
            return *self;
        }
        let mut m = 1;
        let mut po3 = 3;
        while m < *self {
            po3 *= 3;
            m = (po3 - 1) / 2;
        }
        po3 /= 3;
        if m != *self {
            let mut x = *self;
            while x != 0 {
                m = (po3 - 1) / 2;
                po3 /= 3;
                x %= m;
            }
            if m != po3 {
                po3 = m;
            }
        }
        *self - po3
    }

    fn node_z(&self) -> Self {
        let mut m = 1;
        let mut po3 = 3;
        while m < *self {
            po3 *= 3;
            m = (po3 - 1) / 2;
        }
        po3 / 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;
    use tracing::{span, Level};

    #[test]
    fn valid_zero() {
        let _ = span!(Level::INFO, "valid_zero").entered();
        0.is_lipmaa();
    }

    #[test]
    fn lipmaa_one() {
        let _ = span!(Level::INFO, "lipmaa_one").entered();
        assert!(!0.is_lipmaa());
    }

    #[test]
    fn lipmaa_four() {
        let _ = span!(Level::INFO, "lipmaa_four").entered();
        assert!(4.is_lipmaa());
    }
}
