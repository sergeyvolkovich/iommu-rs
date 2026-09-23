//! IOMMU MMIO register map (section 3.3 / 3.4).
//!
//! The register space starts at the base address reported in the IVHD
//! block. Fixed offsets:
//!
//! | Offset  | Register                          |
//! |---------|-----------------------------------|
//! | 0000h   | Device Table Base Address (DTBA)  |
//! | 0008h   | Command Buffer Base (CBBA)        |
//! | 0010h   | Event Log Base (ELBA)             |
//! | 0018h   | Control                           |
//! | 0020h   | Exclusion Base / Completion Store |
//! | 0028h   | Exclusion Limit                   |
//! | 0030h   | Extended Feature Report           |
//! | 0038h   | PPR Log Base (PLBA)               |
//! | 00E0h   | Guest Access Log Base             |
//! | 2000h+  | Head/tail pointers, Status        |
//!
//! Buffer-base registers share the same encoding: bits 51:12 hold the
//! 4 KiB-aligned base, bits 63:56 hold the length encoding
//! (`2^(N+4)` bytes for command/event/PPR logs, `2^(N+1)` entries for the
//! device table).
//!
//! ```
//! use amd_iommu::regs::{CommandBufferBase, Control, Status};
//!
//! // 512-entry (8 KiB) command buffer at 0x1234_5000.
//! let cbba = CommandBufferBase::new(0x1234_5000, 0x9);
//! assert_eq!(cbba.base(), 0x1234_5000);
//! assert_eq!(cbba.length_order(), 0x9);
//! assert_eq!(cbba.size_bytes(), 8192);
//!
//! let ctrl = Control::new(0).with_cmd_buf_en(true).with_iommu_en(true);
//! assert!(ctrl.contains(Control::CMD_BUF_EN | Control::IOMMU_EN));
//! ```

use crate::bits::extract_bits;
use bitflags::bitflags;

// -- fixed register offsets (section 3.3) ------------------------------------

/// Device Table Base Address register.
pub const DEV_TABLE_BASE: u64 = 0x0000;
/// Command Buffer Base Address register.
pub const CMD_BUF_BASE: u64 = 0x0008;
/// Event Log Base Address register.
pub const EVT_BUF_BASE: u64 = 0x0010;
/// Control register.
pub const CONTROL: u64 = 0x0018;
/// Exclusion base / completion store base register.
pub const EXCL_BASE: u64 = 0x0020;
/// Exclusion range limit register.
pub const EXCL_LIMIT: u64 = 0x0028;
/// Extended feature report register.
pub const EXT_FEATURES: u64 = 0x0030;
/// PPR Log Base Address register.
pub const PPR_LOG_BASE: u64 = 0x0038;
/// Guest Access Log Base register.
pub const GA_LOG_BASE: u64 = 0x00E0;
/// Command buffer head pointer.
pub const CMD_HEAD: u64 = 0x2000;
/// Command buffer tail pointer.
pub const CMD_TAIL: u64 = 0x2008;
/// Event log head pointer.
pub const EVT_HEAD: u64 = 0x2010;
/// Event log tail pointer.
pub const EVT_TAIL: u64 = 0x2018;
/// Status register.
pub const STATUS: u64 = 0x2020;
/// PPR log head pointer.
pub const PPR_HEAD: u64 = 0x2030;
/// PPR log tail pointer.
pub const PPR_TAIL: u64 = 0x2038;
/// Guest access log head pointer.
pub const GA_HEAD: u64 = 0x2040;
/// Guest access log tail pointer.
pub const GA_TAIL: u64 = 0x2048;

/// Compute the address of buffer entry `n` for a 16-byte-entry buffer.
#[must_use]
pub const fn entry_offset(n: u16) -> u64 {
    (n as u64) * 16
}

// -- buffer base encoding ----------------------------------------------------

/// Shared encoding of the device-table / command-buffer / event-log /
/// PPR-log base registers.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BufferBase(pub u64);

impl BufferBase {
    /// Build a base register from a 4 KiB-aligned base and a length order
    /// `N` (stored in bits 63:56).
    #[must_use]
    pub const fn new(base: u64, length_order: u8) -> Self {
        BufferBase((base & 0x000f_ffff_ffff_f000) | ((length_order as u64) << 56))
    }

    /// Base address (bits 51:12).
    #[must_use]
    pub const fn base(&self) -> u64 {
        self.0 & 0x000f_ffff_ffff_f000
    }

    /// Length order (bits 63:56).
    #[must_use]
    pub const fn length_order(&self) -> u8 {
        extract_bits(self.0, 63, 56) as u8
    }

    /// Buffer size in bytes for command/event/PPR logs: `2^(N+4)`.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        1u64 << (self.length_order() as u32 + 4)
    }

    /// Entry count for a device table: `2^(N+1)`.
    #[must_use]
    pub const fn entry_count(&self) -> u64 {
        1u64 << (self.length_order() as u32 + 1)
    }

    /// Raw register value.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }
}

/// Command/Event/PPR Log Base register (same layout as [`BufferBase`]).
pub type CommandBufferBase = BufferBase;
/// Device Table Base register (same layout as [`BufferBase`]).
pub type DeviceTableBase = BufferBase;

// -- control register (section 3.3.7, MMIO offset 0018h) ---------------------

bitflags! {
    /// IOMMU Control Register bits (offsets follow the specification
    /// numbering; several fields are multi-bit and exposed as raw helpers
    /// below).
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct Control: u64 {
        /// IOMMU enable (bit 0).
        const IOMMU_EN = 1 << 0;
        /// HyperTransport tunnel translation enable (bit 1).
        const HT_TUN_EN = 1 << 1;
        /// Event log enable (bit 2).
        const EVT_LOG_EN = 1 << 2;
        /// Event log interrupt enable (bit 3).
        const EVT_INT_EN = 1 << 3;
        /// Completion wait interrupt enable (bit 4).
        const COMWAIT_EN = 1 << 4;
        /// PassPW enable (bit 8).
        const PASSPW_EN = 1 << 8;
        /// ResPassPW enable (bit 9).
        const RESPASSPW_EN = 1 << 9;
        /// Coherent enable (bit 10).
        const COHERENT_EN = 1 << 10;
        /// Isochronous enable (bit 11).
        const ISOC_EN = 1 << 11;
        /// Command buffer enable (bit 12).
        const CMD_BUF_EN = 1 << 12;
        /// PPR log enable (bit 13).
        const PPR_LOG_EN = 1 << 13;
        /// PPR interrupt enable (bit 14).
        const PPR_INT_EN = 1 << 14;
        /// PPR enable (bit 15).
        const PPR_EN = 1 << 15;
        /// Guest translation enable (bit 16).
        const GT_EN = 1 << 16;
        /// Guest access (GA) enable (bit 17).
        const GA_EN = 1 << 17;
        /// Guest MSI address mode (GAM, bit 25).
        const GAM_EN = 1 << 25;
        /// Guest access log enable (bit 28).
        const GA_LOG_EN = 1 << 28;
        /// Guest access interrupt enable (bit 29).
        const GA_INT_EN = 1 << 29;
        /// Enhanced PPR handling enable (bit 45).
        const EPH_EN = 1 << 45;
        /// XT (x2APIC) interrupt enable (bit 50).
        const XT_EN = 1 << 50;
        /// Interrupt cap-XT enable (bit 51).
        const INTCAPXT_EN = 1 << 51;
        /// Guest CR3 table TRP mode (bit 58).
        const GCR3_TRP_MODE = 1 << 58;
        /// IR table cache disable (bit 59).
        const IR_CACHE_DIS = 1 << 59;
        /// SNP AVIC enable (bit 61).
        const SNP_AVIC_EN = 1 << 61;
    }
}

impl Control {
    /// Wrap a raw register value.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Control::from_bits_retain(raw)
    }

    /// Set the IOMMU enable bit.
    #[must_use]
    pub const fn with_iommu_en(self, en: bool) -> Self {
        Self::from_bits_retain((self.bits() & !(1 << 0)) | (en as u64))
    }

    /// Set the command buffer enable bit.
    #[must_use]
    pub const fn with_cmd_buf_en(self, en: bool) -> Self {
        Self::from_bits_retain((self.bits() & !(1 << 12)) | ((en as u64) << 12))
    }

    /// Set the event log enable bit.
    #[must_use]
    pub const fn with_evt_log_en(self, en: bool) -> Self {
        Self::from_bits_retain((self.bits() & !(1 << 2)) | ((en as u64) << 2))
    }

    /// Set the PPR enable bit.
    #[must_use]
    pub const fn with_ppr_en(self, en: bool) -> Self {
        Self::from_bits_retain((self.bits() & !(1 << 15)) | ((en as u64) << 15))
    }

    /// Set the guest translation enable bit.
    #[must_use]
    pub const fn with_gt_en(self, en: bool) -> Self {
        Self::from_bits_retain((self.bits() & !(1 << 16)) | ((en as u64) << 16))
    }

    /// Invalidation timeout (bits 7:5).
    #[must_use]
    pub const fn invalidation_timeout(&self) -> u8 {
        extract_bits(self.bits(), 7, 5) as u8
    }

    /// Set the invalidation timeout.
    #[must_use]
    pub const fn with_invalidation_timeout(self, to: u8) -> Self {
        Control::from_bits_retain(
            (self.bits() & !(0x7 << 5)) | (((to & 0x7) as u64) << 5),
        )
    }
}

// -- status register (section 3.3.8, MMIO offset 2020h) ----------------------

bitflags! {
    /// IOMMU Status Register bits.
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct Status: u64 {
        /// Event log overflow (bit 0).
        const EVT_OVERFLOW = 1 << 0;
        /// Event log interrupt pending (bit 1).
        const EVT_INT = 1 << 1;
        /// Completion wait interrupt pending (bit 2).
        const COM_WAIT_INT = 1 << 2;
        /// Event log running (bit 3).
        const EVT_RUN = 1 << 3;
        /// PPR log overflow (bit 5).
        const PPR_OVERFLOW = 1 << 5;
        /// PPR interrupt pending (bit 6).
        const PPR_INT = 1 << 6;
        /// PPR log running (bit 7).
        const PPR_RUN = 1 << 7;
        /// Guest access log running (bit 8).
        const GA_LOG_RUN = 1 << 8;
        /// Guest access log overflow (bit 9).
        const GA_LOG_OVERFLOW = 1 << 9;
        /// Guest access interrupt pending (bit 10).
        const GA_LOG_INT = 1 << 10;
        /// Command buffer running (CmdBufRun, bit 12).
        const CMD_BUF_RUN = 1 << 12;
    }
}

impl Status {
    /// Wrap a raw register value.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Status::from_bits_retain(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_base_encoding() {
        let b = BufferBase::new(0x1234_5000, 0x9);
        assert_eq!(b.base(), 0x1234_5000);
        assert_eq!(b.size_bytes(), 8192);
        // 512-entry device table: 2^(9+1).
        assert_eq!(b.entry_count(), 1024);
    }

    #[test]
    fn control_roundtrip() {
        let c = Control::new(0)
            .with_iommu_en(true)
            .with_cmd_buf_en(true)
            .with_invalidation_timeout(3);
        assert!(c.contains(Control::IOMMU_EN | Control::CMD_BUF_EN));
        assert_eq!(c.invalidation_timeout(), 3);
    }
}
