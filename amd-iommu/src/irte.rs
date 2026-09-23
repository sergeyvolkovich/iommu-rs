//! Interrupt remapping table entry (IRTE) — section 2.2.5, figure 15.
//!
//! The basic IRTE is 128 bits; the device table points at the table via
//! `IV` / `IntTabLen` / interrupt table root pointer. Interrupts whose
//! IRTE is not present are blocked (or logged, see the DTE `IG` flag).
//!
//! ```
//! use amd_iommu::irte::Irte;
//!
//! let irte = Irte::new()
//!     .with_destination(0x0102_0304)
//!     .with_vector(0x51)
//!     .with_valid(true);
//!
//! let words: [u32; 4] = irte.words();
//! assert_eq!(words[0] & 1, 0); // dword 0 holds the low destination id
//! assert_eq!(words[0] & 0xffff, 0x0304); // destination[15:0]
//! assert_eq!(words[1] & 0xff, 0x02); // destination[23:16]
//! assert_eq!(words[1] & (1 << 16), 1 << 16); // valid
//! assert_eq!(words[2] & 0xff, 0x51); // vector
//! ```

use zerocopy::FromBytes;

/// One interrupt remapping table entry (basic format, 128 bits).
///
/// * dword 0: bits 15:0 destination id (xAPIC) / reserved; bits 63:48
///   reserved.
/// * dword 1: bits 7:0 destination id high part (x2APIC), bits 15:8
///   reserved, bit 16 valid (`V`), bits 63:17 reserved.
/// * dword 2: bits 7:0 vector, bits 15:8 reserved, bit 16 `GQ`? — see
///   spec; bits 31:17 reserved.
/// * dword 3: reserved.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, zerocopy::FromBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
#[repr(C)]
pub struct Irte {
    /// Dword 0.
    pub d0: u32,
    /// Dword 1.
    pub d1: u32,
    /// Dword 2.
    pub d2: u32,
    /// Dword 3.
    pub d3: u32,
}

impl Irte {
    /// A zeroed entry.
    #[must_use]
    pub const fn new() -> Self {
        Irte {
            d0: 0,
            d1: 0,
            d2: 0,
            d3: 0,
        }
    }

    /// Valid flag (dword 1 bit 16).
    #[must_use]
    pub const fn valid(&self) -> bool {
        self.d1 & (1 << 16) != 0
    }

    /// Set the valid flag.
    #[must_use]
    pub const fn with_valid(mut self, v: bool) -> Self {
        self.d1 = (self.d1 & !(1 << 16)) | ((v as u32) << 16);
        self
    }

    /// Destination id (32 bits spanning dword 0 bits 15:0 and dword 1
    /// bits 7:0).
    #[must_use]
    pub const fn destination(&self) -> u32 {
        (self.d0 & 0xffff) | ((self.d1 & 0xff) << 16)
    }

    /// Set the destination id.
    #[must_use]
    pub const fn with_destination(mut self, dst: u32) -> Self {
        self.d0 = (self.d0 & !0xffff) | (dst & 0xffff);
        self.d1 = (self.d1 & !0xff) | ((dst >> 16) & 0xff);
        self
    }

    /// Interrupt vector (dword 2 bits 7:0).
    #[must_use]
    pub const fn vector(&self) -> u8 {
        self.d2 as u8
    }

    /// Set the interrupt vector.
    #[must_use]
    pub const fn with_vector(mut self, vector: u8) -> Self {
        self.d2 = (self.d2 & !0xff) | vector as u32;
        self
    }

    /// Raw words.
    #[must_use]
    pub const fn words(&self) -> [u32; 4] {
        [self.d0, self.d1, self.d2, self.d3]
    }

    /// Interpret `bytes` as an IRTE (returns `None` when too short).
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<&Irte> {
        Irte::ref_from_bytes(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bits::extract_bits;

    #[test]
    fn irte_roundtrip() {
        let irte = Irte::new()
            .with_valid(true)
            .with_destination(0x0001_0203)
            .with_vector(0x51);
        assert!(irte.valid());
        assert_eq!(irte.destination(), 0x0001_0203);
        assert_eq!(irte.vector(), 0x51);
        let w = irte.words();
        assert_eq!(w[0] & 0xffff, 0x0203);
        assert_eq!(w[1] & 0xff, 0x01);
        assert_eq!(extract_bits(w[1] as u64, 16, 16), 1);
    }
}
