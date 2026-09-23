//! Device Table Entry (DTE) — section 4.3.3, figure 7 / table 7.
//!
//! The Device Table is indexed by DeviceID (16 bits) and each entry is
//! **256 bits** (four little-endian qwords):
//!
//! * `q0` (DTE bits 63:0): `V`, `TV`, paging `Mode` (11:9), `HAD` (8:7),
//!   `CXL` (6), `MemAttr` (5:4), host page table root pointer (51:12),
//!   `PPR` (52), `GIOV` (54), `GV` (55), `GLX` (57:56), `GCR3[14:12]`
//!   (60:58), `IR` (61), `IW` (62).
//! * `q1` (DTE bits 127:64): `SATS` (42), `SysMgt` (41:40), `EX` (39),
//!   `SD` (38), `Cache` (37), `GCR3[30:15]` (31:16), IOTLB hint (32),
//!   `GCR3[51:31]` (63:43).
//! * `q2` (DTE bits 191:128): `IV` (0), `IntTabLen` (4:1), `IG` (5),
//!   interrupt table root pointer (51:6), `GuestPagingMode` (55:54),
//!   `InitPass` (56), `EIntPass` (57), `NMIPass` (58), `HPTMode` (59).
//! * `q3` (DTE bits 255:192): `GDeviceID` (31:16), `GuestID` (47:32),
//!   `AttrV` (54), `Mode0FC` (55), `SnoopAttribute` (63:56).
//!
//! ```
//! use amd_iommu::dte::{DeviceTableEntry, PagingMode};
//!
//! let dte = DeviceTableEntry::new()
//!     .with_valid(true)
//!     .with_translation_valid(true)
//!     .with_paging_mode(PagingMode::Level2_4)
//!     .with_host_page_table_root(0x1234_5000)
//!     .with_io_coherent(true)
//!     .with_iw(true)
//!     .with_ir(true);
//!
//! assert!(dte.valid() && dte.translation_valid());
//! assert_eq!(dte.paging_mode(), PagingMode::Level2_4);
//! assert_eq!(dte.host_page_table_root(), 0x1234_5000);
//!
//! // Interrupt remapping: 1024-entry table at 0x00aa_c000.
//! let dte = dte
//!     .with_interrupt_map_valid(true)
//!     .with_interrupt_table_len(10)
//!     .with_interrupt_table_ptr(0x00aa_c000);
//! assert_eq!(dte.interrupt_table_len(), 10);
//! assert_eq!(dte.interrupt_table_ptr(), 0x00aa_c000);
//! ```

use crate::bits::extract_bits;

/// Host page-table paging mode (`Mode`, bits 11:9).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum PagingMode {
    /// Translation disabled for this device (000b).
    #[default]
    Disabled,
    /// Reserved (001b).
    Reserved1,
    /// v1 page tables, 3-level (010b).
    Level1_3,
    /// v1 page tables, 4-level (011b).
    Level1_4,
    /// Reserved (100b).
    Reserved4,
    /// v2 page tables, 4-level AMD64 (101b).
    Level2_4,
    /// v2 page tables, 5-level AMD64 (110b).
    Level2_5,
    /// Reserved (111b).
    Reserved7,
}

impl PagingMode {
    /// Decode from the raw 3-bit field.
    #[must_use]
    pub const fn from_bits(v: u8) -> Self {
        match v & 0x7 {
            0 => PagingMode::Disabled,
            1 => PagingMode::Reserved1,
            2 => PagingMode::Level1_3,
            3 => PagingMode::Level1_4,
            4 => PagingMode::Reserved4,
            5 => PagingMode::Level2_4,
            6 => PagingMode::Level2_5,
            _ => PagingMode::Reserved7,
        }
    }

    /// Raw 3-bit encoding.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            PagingMode::Disabled => 0,
            PagingMode::Reserved1 => 1,
            PagingMode::Level1_3 => 2,
            PagingMode::Level1_4 => 3,
            PagingMode::Reserved4 => 4,
            PagingMode::Level2_4 => 5,
            PagingMode::Level2_5 => 6,
            PagingMode::Reserved7 => 7,
        }
    }

    /// `true` when the mode enables translation (v1 or v2).
    #[must_use]
    pub const fn translates(self) -> bool {
        matches!(
            self,
            PagingMode::Level1_3 | PagingMode::Level1_4 | PagingMode::Level2_4 | PagingMode::Level2_5
        )
    }
}

/// System management message handling (`SysMgt`, bits 105:104).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum SysMgt {
    /// `00b` — target abort system-management transactions.
    #[default]
    TargetAbort,
    /// `01b` — forward all system-management messages untranslated.
    ForwardAll,
    /// `10b` — forward INTx only.
    ForwardIntx,
    /// `11b` — translate system-management address range.
    Translate,
}

impl SysMgt {
    /// Decode from the raw 2-bit field.
    #[must_use]
    pub const fn from_bits(v: u8) -> Self {
        match v & 0x3 {
            1 => SysMgt::ForwardAll,
            2 => SysMgt::ForwardIntx,
            3 => SysMgt::Translate,
            _ => SysMgt::TargetAbort,
        }
    }

    /// Raw 2-bit encoding.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            SysMgt::TargetAbort => 0,
            SysMgt::ForwardAll => 1,
            SysMgt::ForwardIntx => 2,
            SysMgt::Translate => 3,
        }
    }
}

/// Device Table Entry — 256 bits (section 4.3.3).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, zerocopy::FromBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
#[repr(C)]
pub struct DeviceTableEntry {
    /// DTE bits 63:0.
    pub q0: u64,
    /// DTE bits 127:64.
    pub q1: u64,
    /// DTE bits 191:128.
    pub q2: u64,
    /// DTE bits 255:192.
    pub q3: u64,
}

impl DeviceTableEntry {
    /// A fully zeroed (not valid) entry.
    #[must_use]
    pub const fn new() -> Self {
        DeviceTableEntry {
            q0: 0,
            q1: 0,
            q2: 0,
            q3: 0,
        }
    }

    /// Entry valid (V, bit 0).
    #[must_use]
    pub const fn valid(&self) -> bool {
        self.q0 & 1 != 0
    }

    /// Set the valid flag.
    #[must_use]
    pub const fn with_valid(mut self, v: bool) -> Self {
        self.q0 = (self.q0 & !1) | (v as u8) as u64;
        self
    }

    /// Translation valid (TV, bit 1).
    #[must_use]
    pub const fn translation_valid(&self) -> bool {
        self.q0 & 2 != 0
    }

    /// Set translation valid.
    #[must_use]
    pub const fn with_translation_valid(mut self, v: bool) -> Self {
        self.q0 = (self.q0 & !2) | (((v as u8) as u64) << 1);
        self
    }

    /// Paging mode (Mode, bits 11:9).
    #[must_use]
    pub const fn paging_mode(&self) -> PagingMode {
        PagingMode::from_bits(extract_bits(self.q0, 11, 9) as u8)
    }

    /// Set the paging mode.
    #[must_use]
    pub const fn with_paging_mode(mut self, mode: PagingMode) -> Self {
        self.q0 = (self.q0 & !(0x7 << 9)) | (((mode.bits() & 0x7) as u64) << 9);
        self
    }

    /// Host access descriptor enable (HAD, bits 8:7).
    #[must_use]
    pub const fn had(&self) -> u8 {
        extract_bits(self.q0, 8, 7) as u8
    }

    /// Host page table root pointer (bits 51:12).
    #[must_use]
    pub const fn host_page_table_root(&self) -> u64 {
        self.q0 & 0x000f_ffff_ffff_f000
    }

    /// Set the host page table root pointer (4 KiB aligned).
    #[must_use]
    pub const fn with_host_page_table_root(mut self, addr: u64) -> Self {
        self.q0 = (self.q0 & 0xfff) | (addr & 0x000f_ffff_ffff_f000);
        self
    }

    /// PPR enable (bit 52).
    #[must_use]
    pub const fn ppr_enable(&self) -> bool {
        self.q0 & (1 << 52) != 0
    }

    /// Set PPR enable.
    #[must_use]
    pub const fn with_ppr_enable(mut self, en: bool) -> Self {
        self.q0 = (self.q0 & !(1 << 52)) | (((en as u8) as u64) << 52);
        self
    }

    /// Guest I/O virtual addressing valid (GIOV, bit 54).
    #[must_use]
    pub const fn giov(&self) -> bool {
        self.q0 & (1 << 54) != 0
    }

    /// Guest translation valid (GV, bit 55).
    #[must_use]
    pub const fn guest_translation_valid(&self) -> bool {
        self.q0 & (1 << 55) != 0
    }

    /// Set guest translation valid (implies GIOV handling by software).
    #[must_use]
    pub const fn with_guest_translation_valid(mut self, v: bool) -> Self {
        self.q0 = (self.q0 & !(1 << 55)) | (((v as u8) as u64) << 55);
        self
    }

    /// Guest level size (GLX, bits 57:56).
    #[must_use]
    pub const fn glx(&self) -> u8 {
        extract_bits(self.q0, 57, 56) as u8
    }

    /// Interrupt remapping enable (IR, bit 61).
    #[must_use]
    pub const fn ir(&self) -> bool {
        self.q0 & (1 << 61) != 0
    }

    /// Set interrupt remapping enable.
    #[must_use]
    pub const fn with_ir(mut self, en: bool) -> Self {
        self.q0 = (self.q0 & !(1 << 61)) | (((en as u8) as u64) << 61);
        self
    }

    /// Interrupt width / IWC — IOMMU-wide interrupt cache invalidate (IW,
    /// bit 62).
    #[must_use]
    pub const fn iw(&self) -> bool {
        self.q0 & (1 << 62) != 0
    }

    /// Set IW.
    #[must_use]
    pub const fn with_iw(mut self, en: bool) -> Self {
        self.q0 = (self.q0 & !(1 << 62)) | (((en as u8) as u64) << 62);
        self
    }

    /// I/O coherent (bit 10 of q0? no — Coherent is control-register side;
    /// this is the SD snoop-disable complement) — snoop disable (SD,
    /// DTE bit 102).
    #[must_use]
    pub const fn snoop_disable(&self) -> bool {
        self.q1 & (1 << 38) != 0
    }

    /// Set snoop disable.
    #[must_use]
    pub const fn with_snoop_disable(mut self, en: bool) -> Self {
        self.q1 = (self.q1 & !(1 << 38)) | (((en as u8) as u64) << 38);
        self
    }

    /// Alias `io_coherent` naming used by some drivers: `true` when walks
    /// are snooped (SD = 0).
    #[must_use]
    pub const fn io_coherent(&self) -> bool {
        !self.snoop_disable()
    }

    /// Set I/O coherence via SD.
    #[must_use]
    pub const fn with_io_coherent(self, coherent: bool) -> Self {
        self.with_snoop_disable(!coherent)
    }

    // -- q1: guest CR3 table --------------------------------------------

    /// Guest CR3 table root pointer (GCR3, bits 51:12) assembled from its
    /// three stored chunks (DTE bits 60:58, 95:80, 127:107).
    #[must_use]
    pub const fn guest_cr3_table(&self) -> u64 {
        let a = extract_bits(self.q0, 60, 58) & 0x7; // ptr[14:12]
        let b = extract_bits(self.q1, 31, 16); // ptr[30:15]
        let c = extract_bits(self.q1, 63, 43); // ptr[51:31]
        (c << 31) | (b << 15) | (a << 12)
    }

    /// Set the guest CR3 table root pointer (8-byte aligned) into the
    /// three chunks.
    #[must_use]
    pub const fn with_guest_cr3_table(mut self, addr: u64) -> Self {
        let p = addr >> 12;
        self.q0 = (self.q0 & !(0x7 << 58)) | ((p & 0x7) << 58);
        self.q1 = (self.q1 & !(0xffff << 16)) | (((p >> 3) & 0xffff) << 16);
        self.q1 = (self.q1 & !(0x1f_ffff << 43)) | (((p >> 19) & 0x1f_ffff) << 43);
        self
    }

    // -- q2: interrupt remapping ----------------------------------------

    /// Interrupt map valid (IV, DTE bit 128).
    #[must_use]
    pub const fn interrupt_map_valid(&self) -> bool {
        self.q2 & 1 != 0
    }

    /// Set interrupt map valid.
    #[must_use]
    pub const fn with_interrupt_map_valid(mut self, v: bool) -> Self {
        self.q2 = (self.q2 & !1) | (v as u8) as u64;
        self
    }

    /// Interrupt table length (IntTabLen, DTE bits 132:129): the table
    /// holds `2^(len+1)` entries when IV = 1 and IntCtl = 10b.
    #[must_use]
    pub const fn interrupt_table_len(&self) -> u8 {
        extract_bits(self.q2, 4, 1) as u8
    }

    /// Set the interrupt table length order.
    #[must_use]
    pub const fn with_interrupt_table_len(mut self, len: u8) -> Self {
        self.q2 = (self.q2 & !(0xf << 1)) | (((len & 0xf) as u64) << 1);
        self
    }

    /// Interrupt table root pointer (DTE bits 179:134, 128-byte aligned).
    #[must_use]
    pub const fn interrupt_table_ptr(&self) -> u64 {
        extract_bits(self.q2, 51, 6) << 7
    }

    /// Set the interrupt table root pointer (128-byte aligned).
    #[must_use]
    pub const fn with_interrupt_table_ptr(mut self, addr: u64) -> Self {
        let bits = (addr >> 7) & 0x3_ffff_ffff;
        self.q2 = (self.q2 & !(0x3f_ffff_ffff << 6)) | (bits << 6);
        self
    }

    /// Guest paging mode start level (DTE bits 183:182): 0 = 4-level
    /// PML4, 1 = 5-level PML5.
    #[must_use]
    pub const fn guest_paging_mode(&self) -> u8 {
        extract_bits(self.q2, 55, 54) as u8
    }

    /// Set guest paging mode start level.
    #[must_use]
    pub const fn with_guest_paging_mode(mut self, mode: u8) -> Self {
        self.q2 = (self.q2 & !(0x3 << 54)) | (((mode & 0x3) as u64) << 54);
        self
    }

    /// INIT pass-through (DTE bit 184).
    #[must_use]
    pub const fn init_pass(&self) -> bool {
        self.q2 & (1 << 56) != 0
    }

    /// ExtINT pass-through (DTE bit 185).
    #[must_use]
    pub const fn extint_pass(&self) -> bool {
        self.q2 & (1 << 57) != 0
    }

    /// NMI pass-through (DTE bit 186).
    #[must_use]
    pub const fn nmi_pass(&self) -> bool {
        self.q2 & (1 << 58) != 0
    }

    // -- q3: guest identifiers -------------------------------------------

    /// Guest device ID (GDeviceID, DTE bits 223:208).
    #[must_use]
    pub const fn guest_device_id(&self) -> u16 {
        extract_bits(self.q3, 31, 16) as u16
    }

    /// Set the guest device ID.
    #[must_use]
    pub const fn with_guest_device_id(mut self, id: u16) -> Self {
        self.q3 = (self.q3 & !(0xffff << 16)) | ((id as u64) << 16);
        self
    }

    /// Guest ID (GuestID, DTE bits 239:224).
    #[must_use]
    pub const fn guest_id(&self) -> u16 {
        extract_bits(self.q3, 47, 32) as u16
    }

    /// Set the guest ID.
    #[must_use]
    pub const fn with_guest_id(mut self, id: u16) -> Self {
        self.q3 = (self.q3 & !(0xffff << 32)) | ((id as u64) << 32);
        self
    }

    /// Raw 32 bytes, little-endian, ready to store in the device table.
    #[must_use]
    pub fn into_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&self.q0.to_le_bytes());
        out[8..16].copy_from_slice(&self.q1.to_le_bytes());
        out[16..24].copy_from_slice(&self.q2.to_le_bytes());
        out[24..].copy_from_slice(&self.q3.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dte_roundtrip() {
        let dte = DeviceTableEntry::new()
            .with_valid(true)
            .with_translation_valid(true)
            .with_paging_mode(PagingMode::Level2_5)
            .with_host_page_table_root(0x1234_5678_9000)
            .with_ppr_enable(true)
            .with_guest_translation_valid(true)
            .with_ir(true);
        assert!(dte.valid());
        assert_eq!(dte.paging_mode(), PagingMode::Level2_5);
        assert_eq!(dte.host_page_table_root(), 0x1234_5678_9000);
        assert!(dte.ppr_enable());
        assert!(dte.guest_translation_valid());
        assert!(dte.ir());
        // V and TV are the low two bits.
        assert_eq!(dte.q0 & 0x3, 0x3);
        assert_eq!(extract_bits(dte.q0, 11, 9), 6);
    }

    #[test]
    fn gcr3_packing() {
        // The GCR3 root pointer is stored with 4 KiB granularity.
        let ptr = 0x1234_5000;
        let dte = DeviceTableEntry::new()
            .with_guest_translation_valid(true)
            .with_guest_cr3_table(ptr);
        assert_eq!(dte.guest_cr3_table(), ptr);
    }

    #[test]
    fn interrupt_table_fields() {
        let dte = DeviceTableEntry::new()
            .with_interrupt_map_valid(true)
            .with_interrupt_table_len(10)
            .with_interrupt_table_ptr(0x00aa_c000);
        assert!(dte.interrupt_map_valid());
        assert_eq!(dte.interrupt_table_len(), 10);
        assert_eq!(dte.interrupt_table_ptr(), 0x00aa_c000);
    }
}
