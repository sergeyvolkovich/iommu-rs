//! Tiny bit-extraction helpers shared by all register/structure decoders.

/// Extract bits `hi..=lo` (inclusive, `lo` = least significant) from `value`.
///
/// The result is right-aligned. `hi - lo` must be `< 64`.
#[inline]
#[must_use]
pub const fn extract_bits(value: u64, hi: u8, lo: u8) -> u64 {
    debug_assert!(hi >= lo);
    debug_assert!(hi - lo < 64);
    let width = (hi - lo + 1) as u32;
    let mask = if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    (value >> lo) & mask
}

/// Number of significant bits (`hi..=lo`) — convenience for assertions.
#[inline]
#[must_use]
pub const fn bits_of(hi: u8, lo: u8) -> u32 {
    (hi - lo + 1) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_single_bits() {
        assert_eq!(extract_bits(0b1010_0001, 7, 0), 0b1010_0001);
        assert_eq!(extract_bits(0b1010_0001, 7, 7), 1);
        assert_eq!(extract_bits(0b1010_0001, 6, 6), 0);
    }

    #[test]
    fn extracts_wide_fields() {
        let v = 0x0123_4567_89ab_cdef;
        assert_eq!(extract_bits(v, 63, 32), 0x0123_4567);
        assert_eq!(extract_bits(v, 31, 0), 0x89ab_cdef);
        assert_eq!(extract_bits(v, 51, 12), (v >> 12) & 0xff_ff_ff_ff_ff);
    }

    #[test]
    fn full_width_field() {
        assert_eq!(extract_bits(0xdead_beef_cafe_babe, 63, 0), 0xdead_beef_cafe_babe);
    }
}
