//! Shared bit-extraction helpers.

/// Extract bits `hi..=lo` (inclusive, `lo` = least significant) from `value`.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_fields() {
        assert_eq!(extract_bits(0b1010_0001, 7, 0), 0b1010_0001);
        assert_eq!(extract_bits(0b1010_0001, 7, 7), 1);
        assert_eq!(extract_bits(0x0123_4567_89ab_cdef, 63, 32), 0x0123_4567);
        assert_eq!(
            extract_bits(0x0123_4567_89ab_cdef, 51, 12),
            (0x0123_4567_89ab_cdef >> 12) & 0xff_ff_ff_ff_ff
        );
    }
}
