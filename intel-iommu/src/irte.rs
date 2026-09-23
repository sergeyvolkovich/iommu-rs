//! Interrupt remapping table entries (section 9.9 / 9.10).
//!
//! Interrupt remapping translates DMA interrupt requests through the
//! interrupt remapping table (IRTA). Entry layout depends on
//! `IRTA_REG.EIME`:
//!
//! * **Remapped** (figure 9-9): interrupt is re-injected with a new
//!   destination/vector (`IM` = 0).
//! * **Posted** (figure 9-10): interrupt is recorded into a posted
//!   interrupt descriptor in memory (`IM` = 1).
//!
//! Both formats are architecturally 128 bits; with `EIME = 0` only the low
//! 64 bits are interpreted for remapped entries.
//!
//! ```
//! use intel_iommu::irte::{Irte, DeliveryMode, IrteMode};
//!
//! let irte = Irte::new_remapped()
//!     .with_destination(0x1234_5678)      // x2APIC destination
//!     .with_vector(0x40)
//!     .with_delivery_mode(DeliveryMode::Fixed)
//!     .with_source_id(0x0bad)
//!     .with_present(true);
//!
//! assert_eq!(irte.mode(), IrteMode::Remapped);
//! assert_eq!(irte.vector(), 0x40);
//! assert_eq!(irte.destination_id(), 0x1234_5678);
//!
//! let words: [u64; 2] = irte.words();
//! assert_eq!(words[0] & 1, 1);
//! ```

use crate::bits::extract_bits;
use core::fmt;

/// IRTE mode (bit 15): remapped or posted.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum IrteMode {
    /// Remapped format (0).
    #[default]
    Remapped,
    /// Posted format (1).
    Posted,
}

impl IrteMode {
    /// Decode from bit 15.
    #[must_use]
    pub const fn from_bit(im: bool) -> Self {
        if im {
            IrteMode::Posted
        } else {
            IrteMode::Remapped
        }
    }
}

/// Delivery mode (`DLM`, bits 7:5 of a remapped IRTE).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum DeliveryMode {
    /// `000b` — deliver to all indicated agents (edge or level).
    #[default]
    Fixed,
    /// `001b` — deliver to one agent of lowest priority.
    LowestPriority,
    /// `010b` — system management interrupt (edge).
    Smi,
    /// `100b` — non-maskable interrupt (edge).
    Nmi,
    /// `101b` — INIT (edge).
    Init,
    /// `111b` — ExtINT, 8259A compatibility (edge).
    ExtInt,
    /// Any other / reserved encoding.
    Reserved(u8),
}

impl DeliveryMode {
    /// Decode from the raw 3-bit field.
    #[must_use]
    pub const fn from_bits(v: u8) -> Self {
        match v & 0x7 {
            0 => DeliveryMode::Fixed,
            1 => DeliveryMode::LowestPriority,
            2 => DeliveryMode::Smi,
            4 => DeliveryMode::Nmi,
            5 => DeliveryMode::Init,
            7 => DeliveryMode::ExtInt,
            other => DeliveryMode::Reserved(other),
        }
    }

    /// Raw 3-bit encoding.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            DeliveryMode::Fixed => 0,
            DeliveryMode::LowestPriority => 1,
            DeliveryMode::Smi => 2,
            DeliveryMode::Nmi => 4,
            DeliveryMode::Init => 5,
            DeliveryMode::ExtInt => 7,
            DeliveryMode::Reserved(v) => v & 0x7,
        }
    }
}

/// Source validation type (`SVT`, bits 83:82).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum SourceValidationType {
    /// `00b` — no source-id validation.
    #[default]
    NoValidation,
    /// `01b` — reserved encoding.
    Reserved01,
    /// `10b` — verify bus (most significant 8 bits of requester id).
    VerifyBus,
    /// `11b` — verify full requester id (bus + device + function).
    VerifyFull,
}

impl SourceValidationType {
    /// Decode from the raw 2-bit field.
    #[must_use]
    pub const fn from_bits(v: u8) -> Self {
        match v & 0x3 {
            0 => SourceValidationType::NoValidation,
            1 => SourceValidationType::Reserved01,
            2 => SourceValidationType::VerifyBus,
            _ => SourceValidationType::VerifyFull,
        }
    }

    /// Raw 2-bit encoding.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            SourceValidationType::NoValidation => 0,
            SourceValidationType::Reserved01 => 1,
            SourceValidationType::VerifyBus => 2,
            SourceValidationType::VerifyFull => 3,
        }
    }
}

/// Source qualifier (`SQ`, bits 81:80) — which part of the requester id is
/// compared during source validation.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum SourceQualifier {
    /// `00b` — compare the full 16-bit source id.
    #[default]
    FullId,
    /// `01b` — compare bus + device, ignore function.
    IgnoreFunction,
    /// `10b` — compare bus only.
    BusOnly,
    /// `11b` — reserved.
    Reserved,
}

impl SourceQualifier {
    /// Decode from the raw 2-bit field.
    #[must_use]
    pub const fn from_bits(v: u8) -> Self {
        match v & 0x3 {
            0 => SourceQualifier::FullId,
            1 => SourceQualifier::IgnoreFunction,
            2 => SourceQualifier::BusOnly,
            _ => SourceQualifier::Reserved,
        }
    }

    /// Raw 2-bit encoding.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            SourceQualifier::FullId => 0,
            SourceQualifier::IgnoreFunction => 1,
            SourceQualifier::BusOnly => 2,
            SourceQualifier::Reserved => 3,
        }
    }
}

/// One interrupt remapping table entry (128 bits).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, zerocopy::FromBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
#[repr(C)]
pub struct Irte {
    /// Low qword (entry bits 63:0).
    pub low: u64,
    /// High qword (entry bits 127:64): SID, SQ, SVT (+ PDA for posted).
    pub high: u64,
}

impl Irte {
    /// Start building a remapped-format entry.
    #[must_use]
    pub const fn new_remapped() -> Self {
        Irte { low: 0, high: 0 }
    }

    /// Start building a posted-format entry (`IM` = 1).
    #[must_use]
    pub const fn new_posted() -> Self {
        Irte {
            low: 1 << 15,
            high: 0,
        }
    }

    /// IRTE mode (bit 15).
    #[must_use]
    pub const fn mode(&self) -> IrteMode {
        IrteMode::from_bit(self.low & (1 << 15) != 0)
    }

    /// Present flag (bit 0).
    #[must_use]
    pub const fn present(&self) -> bool {
        self.low & 1 != 0
    }

    /// Set the present flag.
    #[must_use]
    pub const fn with_present(mut self, p: bool) -> Self {
        self.low = (self.low & !1) | (p as u8) as u64;
        self
    }

    /// Fault processing disable (bit 1).
    #[must_use]
    pub const fn fault_disable(&self) -> bool {
        self.low & 2 != 0
    }

    /// Destination mode (bit 2, remapped): physical (0) / logical (1).
    #[must_use]
    pub const fn destination_mode_logical(&self) -> bool {
        self.low & 4 != 0
    }

    /// Redirection hint (bit 3, remapped).
    #[must_use]
    pub const fn redirection_hint(&self) -> bool {
        self.low & 8 != 0
    }

    /// Trigger mode (bit 4, remapped): edge (0) / level (1).
    #[must_use]
    pub const fn trigger_mode_level(&self) -> bool {
        self.low & 0x10 != 0
    }

    /// Set the trigger mode.
    #[must_use]
    pub const fn with_trigger_mode_level(mut self, level: bool) -> Self {
        self.low = (self.low & !0x10) | (((level as u8) as u64) << 4);
        self
    }

    /// Delivery mode (bits 7:5, remapped).
    #[must_use]
    pub const fn delivery_mode(&self) -> DeliveryMode {
        DeliveryMode::from_bits(extract_bits(self.low, 7, 5) as u8)
    }

    /// Set the delivery mode.
    #[must_use]
    pub const fn with_delivery_mode(mut self, dlm: DeliveryMode) -> Self {
        let bits = (dlm.bits()) as u64;
        self.low = (self.low & !(0x7 << 5)) | (bits << 5);
        self
    }

    /// Interrupt vector (bits 23:16, remapped) / virtual vector (bits
    /// 23:16, posted).
    #[must_use]
    pub const fn vector(&self) -> u8 {
        extract_bits(self.low, 23, 16) as u8
    }

    /// Set the interrupt vector.
    #[must_use]
    pub const fn with_vector(mut self, vector: u8) -> Self {
        self.low = (self.low & !(0xff << 16)) | (((vector) as u64) << 16);
        self
    }

    /// Destination ID (bits 63:32, remapped).
    ///
    /// With `EIME = 0` only bits 47:40 (APIC id) are interpreted.
    #[must_use]
    pub const fn destination_id(&self) -> u32 {
        extract_bits(self.low, 63, 32) as u32
    }

    /// Set the destination ID.
    #[must_use]
    pub const fn with_destination(mut self, dst: u32) -> Self {
        self.low = (self.low & !(0xffff_ffff << 32)) | (((dst) as u64) << 32);
        self
    }

    /// Source identifier (bits 79:64 = high qword bits 15:0).
    #[must_use]
    pub const fn source_id(&self) -> u16 {
        self.high as u16
    }

    /// Set the source identifier.
    #[must_use]
    pub const fn with_source_id(mut self, sid: u16) -> Self {
        self.high = (self.high & !0xffff) | (sid) as u64;
        self
    }

    /// Source qualifier (bits 81:80).
    #[must_use]
    pub const fn source_qualifier(&self) -> SourceQualifier {
        SourceQualifier::from_bits(extract_bits(self.high, 17, 16) as u8)
    }

    /// Set the source qualifier.
    #[must_use]
    pub const fn with_source_qualifier(mut self, sq: SourceQualifier) -> Self {
        let bits = (sq.bits()) as u64;
        self.high = (self.high & !(0x3 << 16)) | (bits << 16);
        self
    }

    /// Source validation type (bits 83:82).
    #[must_use]
    pub const fn source_validation(&self) -> SourceValidationType {
        SourceValidationType::from_bits(extract_bits(self.high, 19, 18) as u8)
    }

    /// Set the source validation type.
    #[must_use]
    pub const fn with_source_validation(mut self, svt: SourceValidationType) -> Self {
        let bits = (svt.bits()) as u64;
        self.high = (self.high & !(0x3 << 18)) | (bits << 18);
        self
    }

    // -- posted format ----------------------------------------------------

    /// Urgent flag (bit 14, posted).
    #[must_use]
    pub const fn urgent(&self) -> bool {
        self.low & (1 << 14) != 0
    }

    /// Set the urgent flag.
    #[must_use]
    pub const fn with_urgent(mut self, urg: bool) -> Self {
        self.low = (self.low & !(1 << 14)) | (((urg as u8) as u64) << 14);
        self
    }

    /// Posted descriptor address low part (bits 63:38 = PDA[31:6]).
    #[must_use]
    pub const fn posted_addr_low(&self) -> u32 {
        (extract_bits(self.low, 63, 38) as u32) << 6
    }

    /// Posted descriptor address high part (bits 127:96 = PDA[63:32]).
    #[must_use]
    pub const fn posted_addr_high(&self) -> u32 {
        extract_bits(self.high, 63, 32) as u32
    }

    /// Full 64-byte aligned posted interrupt descriptor address.
    #[must_use]
    pub const fn posted_descriptor_addr(&self) -> u64 {
        ((self.posted_addr_high() as u64) << 32) | (self.posted_addr_low() as u64)
    }

    /// Set the posted interrupt descriptor address (must be 64-byte
    /// aligned; low 6 bits are implied zero).
    #[must_use]
    pub const fn with_posted_descriptor_addr(mut self, addr: u64) -> Self {
        self.low = (self.low & !(0x3ff_ffff << 38))
            | (((addr >> 6) & 0x3ff_ffff) << 38)
            | (1 << 15);
        self.high = (self.high & !(0xffff_ffff << 32)) | ((addr >> 32) << 32);
        self
    }

    /// Raw words.
    #[must_use]
    pub const fn words(&self) -> [u64; 2] {
        [self.low, self.high]
    }
}

impl fmt::Display for DeliveryMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeliveryMode::Fixed => write!(f, "fixed"),
            DeliveryMode::LowestPriority => write!(f, "lowest-priority"),
            DeliveryMode::Smi => write!(f, "smi"),
            DeliveryMode::Nmi => write!(f, "nmi"),
            DeliveryMode::Init => write!(f, "init"),
            DeliveryMode::ExtInt => write!(f, "extint"),
            DeliveryMode::Reserved(v) => write!(f, "reserved({v})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remapped_roundtrip() {
        let irte = Irte::new_remapped()
            .with_present(true)
            .with_vector(0x51)
            .with_destination(0x1234_5678)
            .with_delivery_mode(DeliveryMode::Nmi)
            .with_trigger_mode_level(true)
            .with_source_id(0x1234)
            .with_source_validation(SourceValidationType::VerifyFull)
            .with_source_qualifier(SourceQualifier::IgnoreFunction);

        let [lo, hi] = irte.words();
        assert_eq!(lo & 1, 1);
        assert_eq!((lo >> 16) & 0xff, 0x51);
        assert_eq!(lo >> 32, 0x1234_5678);
        assert_eq!(extract_bits(lo, 7, 5), 4);
        assert_eq!(hi & 0xffff, 0x1234);
        assert_eq!(extract_bits(hi, 19, 18), 3);
        assert_eq!(extract_bits(hi, 17, 16), 1);
    }

    #[test]
    fn posted_addr_roundtrip() {
        let addr = 0x1234_5678_9abc_def0u64 & !0x3f; // 64-byte aligned
        let irte = Irte::new_posted().with_posted_descriptor_addr(addr);
        assert_eq!(irte.mode(), IrteMode::Posted);
        assert_eq!(irte.posted_descriptor_addr(), addr);
        assert!(irte.posted_addr_low() & 0x3f == 0);
    }
}
