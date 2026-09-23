//! Root, context, PASID-directory and PASID-table entries.
//!
//! Covers both translation-table modes selected by `RTADDR_REG.TTM`:
//!
//! * **Legacy** (sections 9.1/9.3): 128-bit root entries referencing
//!   128-bit context entries.
//! * **Scalable** (sections 9.2/9.4–9.6): 128-bit root entries referencing
//!   256-bit scalable context entries, which point to a two-level PASID
//!   directory / PASID table of 512-bit entries.
//!
//! All entry types are plain `#[repr(C)]` wrappers over their
//! little-endian representation and can be overlayed on DMA-coherent
//! memory with `zerocopy::FromBytes` on little-endian targets (which is
//! every target that implements VT-d).
//!
//! ```
//! use intel_iommu::context::{ContextEntry, RootEntry, TransType, AddrWidth};
//!
//! // A legacy context entry mapping domain 5 via a 4-level second-stage
//! // table at physical 0x12345000.
//! let ce = ContextEntry::new()
//!     .with_domain_id(5)
//!     .with_address_width(AddrWidth::Agaw48)
//!     .with_second_stage_ptr(0x1234_5000)
//!     .with_translation_type(TransType::SecondStage)
//!     .with_present(true);
//! assert!(ce.present());
//! assert_eq!(ce.domain_id(), 5);
//!
//! // Raw wire form, ready to be stored into the context table.
//! let raw: [u8; 16] = ce.into_bytes();
//! assert_eq!(raw[0] & 1, 1);
//! ```

use crate::bits::extract_bits;
use core::fmt;
use zerocopy::{FromBytes, Immutable, KnownLayout};

// ---------------------------------------------------------------------------
// Legacy root entry (section 9.1) — 128 bits
// ---------------------------------------------------------------------------

/// Legacy-mode root table entry (128 bits).
///
/// Only one present bit and the context-table pointer are defined; the rest
/// is reserved and must be zero.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RootEntry {
    /// Low qword: present bit + context table pointer.
    pub low: u64,
    /// High qword: reserved (0).
    pub high: u64,
}

impl RootEntry {
    /// Create a root entry pointing at a 4 KiB-aligned context table.
    #[must_use]
    pub fn new(context_table: u64) -> Self {
        RootEntry {
            low: (context_table & !0xfff) | 1,
            high: 0,
        }
    }

    /// Present flag.
    #[must_use]
    pub const fn present(&self) -> bool {
        self.low & 1 != 0
    }

    /// Context table base address (bits 63:12).
    #[must_use]
    pub const fn context_table(&self) -> u64 {
        self.low & !0xfff
    }
}

/// Scalable-mode root table entry (128 bits, section 9.2).
///
/// Identical wire layout to [`RootEntry`] but references a *scalable*
/// context table; kept as a distinct type for clarity and safety.
pub type ScalableRootEntry = RootEntry;

// ---------------------------------------------------------------------------
// Legacy context entry (section 9.3) — 128 bits
// ---------------------------------------------------------------------------

/// Adjusted guest address width (`AW`, bits 66:64 of the context entry).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AddrWidth {
    /// Reserved encoding (000b).
    Reserved0,
    /// 39-bit AGAW, 3-level page table (001b).
    Agaw39,
    /// 48-bit AGAW, 4-level page table (010b).
    Agaw48,
    /// 57-bit AGAW, 5-level page table (011b).
    Agaw57,
    /// Any other reserved encoding.
    Reserved(u8),
}

impl AddrWidth {
    /// Decode from the raw 3-bit field (const context helper).
    #[must_use]
    pub const fn from_bits(v: u8) -> Self {
        match v & 0x7 {
            1 => AddrWidth::Agaw39,
            2 => AddrWidth::Agaw48,
            3 => AddrWidth::Agaw57,
            0 => AddrWidth::Reserved0,
            other => AddrWidth::Reserved(other),
        }
    }

    /// Raw 3-bit encoding.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            AddrWidth::Reserved0 => 0,
            AddrWidth::Agaw39 => 1,
            AddrWidth::Agaw48 => 2,
            AddrWidth::Agaw57 => 3,
            AddrWidth::Reserved(v) => v & 0x7,
        }
    }

    /// Number of address bits covered by this AGAW.
    #[must_use]
    pub const fn address_bits(self) -> u32 {
        match self {
            AddrWidth::Agaw39 => 39,
            AddrWidth::Agaw48 => 48,
            AddrWidth::Agaw57 => 57,
            _ => 0,
        }
    }
}

impl From<u8> for AddrWidth {
    fn from(v: u8) -> Self {
        AddrWidth::from_bits(v)
    }
}

impl fmt::Display for AddrWidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrWidth::Agaw39 => write!(f, "39-bit (3-level)"),
            AddrWidth::Agaw48 => write!(f, "48-bit (4-level)"),
            AddrWidth::Agaw57 => write!(f, "57-bit (5-level)"),
            other => write!(f, "reserved ({:x})", other.bits()),
        }
    }
}

/// Translation type (`TT`, bits 3:2 of the context entry).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum TransType {
    /// `00b` — untranslated requests translated through `SSPTPTR`.
    #[default]
    SecondStage,
    /// `01b` — reserved encoding in current specs (legacy sys-mgmt).
    Reserved01,
    /// `10b` — pass-through (requests bypass translation).
    PassThrough,
    /// `11b` — reserved.
    Reserved11,
}

impl TransType {
    /// Decode from the raw 2-bit field (const context helper).
    #[must_use]
    pub const fn from_bits(v: u8) -> Self {
        match v & 0x3 {
            0 => TransType::SecondStage,
            1 => TransType::Reserved01,
            2 => TransType::PassThrough,
            _ => TransType::Reserved11,
        }
    }

    /// Raw 2-bit encoding.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            TransType::SecondStage => 0,
            TransType::Reserved01 => 1,
            TransType::PassThrough => 2,
            TransType::Reserved11 => 3,
        }
    }
}

impl From<u8> for TransType {
    fn from(v: u8) -> Self {
        TransType::from_bits(v)
    }
}

/// Legacy-mode context entry (128 bits, section 9.3, figure 9-3).
///
/// | Bits   | Field      |
/// |--------|------------|
/// | 87:72  | DID        |
/// | 70:67  | IGN        |
/// | 66:64  | AW         |
/// | 63:12  | SSPTPTR    |
/// | 3:2    | TT         |
/// | 1      | FPD        |
/// | 0      | P          |
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct ContextEntry {
    /// Qword 0: P, FPD, TT, reserved, SSPTPTR.
    pub q0: u64,
    /// Qword 1: AW, IGN, reserved, DID.
    pub q1: u64,
}

impl ContextEntry {
    /// Start building an entry with all fields zeroed (not present).
    #[must_use]
    pub const fn new() -> Self {
        ContextEntry { q0: 0, q1: 0 }
    }

    /// Set the present flag.
    #[must_use]
    pub const fn with_present(mut self, p: bool) -> Self {
        self.q0 = (self.q0 & !1) | (p as u8) as u64;
        self
    }

    /// Present flag.
    #[must_use]
    pub const fn present(&self) -> bool {
        self.q0 & 1 != 0
    }

    /// Set fault-processing disable (bit 1).
    #[must_use]
    pub const fn with_fault_disable(mut self, fpd: bool) -> Self {
        self.q0 = (self.q0 & !2) | (((fpd as u8) as u64) << 1);
        self
    }

    /// Fault-processing disable flag.
    #[must_use]
    pub const fn fault_disable(&self) -> bool {
        self.q0 & 2 != 0
    }

    /// Set the translation type.
    #[must_use]
    pub const fn with_translation_type(mut self, tt: TransType) -> Self {
        self.q0 = (self.q0 & !0xc) | (((tt.bits() as u64) << 2) & 0xc);
        self
    }

    /// Translation type.
    #[must_use]
    pub const fn translation_type(&self) -> TransType {
        TransType::from_bits(extract_bits(self.q0, 3, 2) as u8)
    }

    /// Set the second-stage page-table pointer (bits 63:12).
    #[must_use]
    pub const fn with_second_stage_ptr(mut self, addr: u64) -> Self {
        self.q0 = (self.q0 & 0xfff) | (addr & !0xfff);
        self
    }

    /// Second-stage page-table base address.
    #[must_use]
    pub const fn second_stage_ptr(&self) -> u64 {
        self.q0 & !0xfff
    }

    /// Set the adjusted guest address width (entry bits 66:64 = q1[2:0]).
    #[must_use]
    pub const fn with_address_width(mut self, aw: AddrWidth) -> Self {
        self.q1 = (self.q1 & !0x7) | ((aw.bits() as u64) & 0x7);
        self
    }

    /// Adjusted guest address width.
    #[must_use]
    pub const fn address_width(&self) -> AddrWidth {
        AddrWidth::from_bits(extract_bits(self.q1, 2, 0) as u8)
    }

    /// Set the domain identifier (entry bits 87:72 = q1[23:8]).
    #[must_use]
    pub const fn with_domain_id(mut self, did: u16) -> Self {
        self.q1 = (self.q1 & !(0xffff << 8)) | ((did as u64) << 8);
        self
    }

    /// Domain identifier.
    #[must_use]
    pub const fn domain_id(&self) -> u16 {
        extract_bits(self.q1, 23, 8) as u16
    }

    /// Raw 16 bytes, little-endian, ready to store in the table.
    #[must_use]
    pub fn into_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.q0.to_le_bytes());
        out[8..].copy_from_slice(&self.q1.to_le_bytes());
        out
    }
}

// ---------------------------------------------------------------------------
// Scalable-mode context entry (section 9.4) — 256 bits
// ---------------------------------------------------------------------------

/// Scalable-mode context entry (256 bits, section 9.4, figure 9-4).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct ScalableContextEntry {
    /// Qword 0: P, FPD, DTE, PASIDE, PRE, HPTE, EPTR, PDTS, PASIDDIRPTR.
    pub q0: u64,
    /// Qword 1: RID_PASID (19:0), RID_PRIV (20).
    pub q1: u64,
    /// Qwords 2..3: reserved.
    pub reserved: [u64; 2],
}

impl ScalableContextEntry {
    /// Start building an entry with all fields zeroed.
    #[must_use]
    pub const fn new() -> Self {
        ScalableContextEntry {
            q0: 0,
            q1: 0,
            reserved: [0; 2],
        }
    }

    /// Present flag (bit 0).
    #[must_use]
    pub const fn present(&self) -> bool {
        self.q0 & 1 != 0
    }

    /// Set the present flag.
    #[must_use]
    pub const fn with_present(mut self, p: bool) -> Self {
        self.q0 = (self.q0 & !1) | (p as u8) as u64;
        self
    }

    /// Fault-processing disable (bit 1).
    #[must_use]
    pub const fn fault_disable(&self) -> bool {
        self.q0 & 2 != 0
    }

    /// Device-TLB enable (bit 2).
    #[must_use]
    pub const fn device_tlb_enable(&self) -> bool {
        self.q0 & 4 != 0
    }

    /// PASID enable (bit 3): process requests-with-PASID.
    #[must_use]
    pub const fn pasid_enable(&self) -> bool {
        self.q0 & 8 != 0
    }

    /// Page-request enable (bit 4).
    #[must_use]
    pub const fn page_request_enable(&self) -> bool {
        self.q0 & 0x10 != 0
    }

    /// HPT enable (bit 5).
    #[must_use]
    pub const fn hpt_enable(&self) -> bool {
        self.q0 & 0x20 != 0
    }

    /// Enable PASID in translated requests (bit 6).
    #[must_use]
    pub const fn eptr_enable(&self) -> bool {
        self.q0 & 0x40 != 0
    }

    /// PASID directory size (bits 11:9): directory holds `2^(X+7)` entries.
    #[must_use]
    pub const fn pasid_dir_size(&self) -> u8 {
        extract_bits(self.q0, 11, 9) as u8
    }

    /// Set the PASID directory size order.
    #[must_use]
    pub const fn with_pasid_dir_size(mut self, order: u8) -> Self {
        self.q0 = (self.q0 & !(0x7 << 9)) | (((order & 0x7) as u64) << 9);
        self
    }

    /// Set the PASID directory pointer (bits 63:12).
    #[must_use]
    pub const fn with_pasid_dir_ptr(mut self, addr: u64) -> Self {
        self.q0 = (self.q0 & 0xfff) | (addr & !0xfff);
        self
    }

    /// PASID directory base address.
    #[must_use]
    pub const fn pasid_dir_ptr(&self) -> u64 {
        self.q0 & !0xfff
    }

    /// RID_PASID (entry bits 83:64 = q1[19:0]): PASID used for requests
    /// without PASID.
    #[must_use]
    pub const fn rid_pasid(&self) -> u32 {
        extract_bits(self.q1, 19, 0) as u32
    }

    /// Set RID_PASID.
    #[must_use]
    pub const fn with_rid_pasid(mut self, pasid: u32) -> Self {
        self.q1 = (self.q1 & !0xf_ffff) | ((pasid & 0xf_ffff) as u64);
        self
    }

    /// RID_PRIV (entry bit 84 = q1[20]): privilege-mode requested for
    /// RID_PASID requests.
    #[must_use]
    pub const fn rid_priv(&self) -> bool {
        self.q1 & (1 << 20) != 0
    }

    /// Set RID_PRIV.
    #[must_use]
    pub const fn with_rid_priv(mut self, en: bool) -> Self {
        self.q1 = (self.q1 & !(1 << 20)) | (((en as u8) as u64) << 20);
        self
    }
}

// ---------------------------------------------------------------------------
// PASID directory entry (section 9.5) — 128 bits
// ---------------------------------------------------------------------------

/// Scalable-mode PASID directory entry (128 bits, figure 9-5).
///
/// Bits 63:12 hold the scalable-mode PASID-table pointer, bit 0 is the
/// present flag, bit 1 is FPD.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct PasidDirEntry {
    /// Low qword: P (0), FPD (1), SMPTBLPTR (63:12).
    pub low: u64,
    /// High qword: reserved.
    pub high: u64,
}

impl PasidDirEntry {
    /// Create a present entry pointing at a PASID table.
    #[must_use]
    pub fn new(pasid_table: u64) -> Self {
        PasidDirEntry {
            low: (pasid_table & !0xfff) | 1,
            high: 0,
        }
    }

    /// Present flag.
    #[must_use]
    pub const fn present(&self) -> bool {
        self.low & 1 != 0
    }

    /// Fault-processing disable.
    #[must_use]
    pub const fn fault_disable(&self) -> bool {
        self.low & 2 != 0
    }

    /// PASID table base address.
    #[must_use]
    pub const fn pasid_table_ptr(&self) -> u64 {
        self.low & !0xfff
    }
}

// ---------------------------------------------------------------------------
// PASID table entry (section 9.6) — 512 bits
// ---------------------------------------------------------------------------

/// PASID granular translation type (`PGTT`, bits 8:6 of PASID entry qword 0).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Pgtt {
    /// Reserved (000b).
    #[default]
    Reserved0,
    /// First-stage only (001b).
    FirstStageOnly,
    /// Second-stage only (010b).
    SecondStageOnly,
    /// Nested translation (011b).
    Nested,
    /// Pass-through (100b).
    PassThrough,
    /// Any other reserved encoding.
    Reserved(u8),
}

impl Pgtt {
    /// Decode from the raw 3-bit field (const context helper).
    #[must_use]
    pub const fn from_bits(v: u8) -> Self {
        match v & 0x7 {
            1 => Pgtt::FirstStageOnly,
            2 => Pgtt::SecondStageOnly,
            3 => Pgtt::Nested,
            4 => Pgtt::PassThrough,
            0 => Pgtt::Reserved0,
            other => Pgtt::Reserved(other),
        }
    }

    /// Raw 3-bit encoding.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Pgtt::Reserved0 => 0,
            Pgtt::FirstStageOnly => 1,
            Pgtt::SecondStageOnly => 2,
            Pgtt::Nested => 3,
            Pgtt::PassThrough => 4,
            Pgtt::Reserved(v) => v & 0x7,
        }
    }
}

impl From<u8> for Pgtt {
    fn from(v: u8) -> Self {
        Pgtt::from_bits(v)
    }
}

/// First-level paging mode (`FLPM`, PASID entry qword 2 bits 3:2).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Flpm {
    /// 4-level first-stage paging (00b).
    #[default]
    FourLevel,
    /// 5-level first-stage paging (01b).
    FiveLevel,
    /// Reserved encodings (10b/11b).
    Reserved(u8),
}

impl Flpm {
    /// Decode from the raw 2-bit field.
    #[must_use]
    pub const fn from_bits(v: u8) -> Self {
        match v & 0x3 {
            0 => Flpm::FourLevel,
            1 => Flpm::FiveLevel,
            other => Flpm::Reserved(other),
        }
    }

    /// Raw 2-bit encoding.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Flpm::FourLevel => 0,
            Flpm::FiveLevel => 1,
            Flpm::Reserved(v) => v & 0x3,
        }
    }
}

/// Scalable-mode PASID table entry (section 9.6, figure 9-6).
///
/// The architecturally defined entry is **512 bits** (64 bytes):
///
/// * qword 0 (entry bits 63:0): `P`, `FPD`, `AW` (4:2), `PGTT` (8:6),
///   `SSADE` (9) and the page-table pointer (63:12).
/// * qword 1 (entry bits 127:64): `DID` (15:0), `PGSNP` (24), `CD` (25).
/// * qword 2 (entry bits 191:128): `SRE` (0), `FLPM` (3:2), `WPE` (4),
///   `EAFE` (7).
/// * qword 3 (entry bits 255:192): reserved.
/// * qwords 4..7 (entry bits 511:256): HPT fields (`HPTPTR`, `HPTSZ`,
///   `HPTDID`) used only when `HPTE` is set in the scalable context entry.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct PasidTableEntry {
    /// Qword 0: P, FPD, AW, PGTT, SSADE, page-table pointer.
    pub q0: u64,
    /// Qword 1: DID, PGSNP, CD.
    pub q1: u64,
    /// Qword 2: SRE, FLPM, WPE, EAFE.
    pub q2: u64,
    /// Qword 3: reserved.
    pub q3: u64,
    /// Qwords 4..7: HPT fields (raw when HPT is not in use).
    pub hpt: [u64; 4],
}

impl PasidTableEntry {
    /// Start building an entry with all fields zeroed.
    #[must_use]
    pub const fn new() -> Self {
        PasidTableEntry {
            q0: 0,
            q1: 0,
            q2: 0,
            q3: 0,
            hpt: [0; 4],
        }
    }

    /// Present flag (bit 0).
    #[must_use]
    pub const fn present(&self) -> bool {
        self.q0 & 1 != 0
    }

    /// Set the present flag.
    #[must_use]
    pub const fn with_present(mut self, p: bool) -> Self {
        self.q0 = (self.q0 & !1) | (p as u8) as u64;
        self
    }

    /// Fault-processing disable (bit 1).
    #[must_use]
    pub const fn fault_disable(&self) -> bool {
        self.q0 & 2 != 0
    }

    /// Second-stage accessed/dirty enable (SSADE/SLADE, bit 9).
    #[must_use]
    pub const fn ss_accessed_dirty(&self) -> bool {
        self.q0 & (1 << 9) != 0
    }

    /// Set second-stage accessed/dirty enable.
    #[must_use]
    pub const fn with_ss_accessed_dirty(mut self, en: bool) -> Self {
        self.q0 = (self.q0 & !(1 << 9)) | (((en as u8) as u64) << 9);
        self
    }

    /// PASID granular translation type (PGTT, bits 8:6).
    #[must_use]
    pub const fn pgtt(&self) -> Pgtt {
        Pgtt::from_bits(extract_bits(self.q0, 8, 6) as u8)
    }

    /// Set the PASID granular translation type.
    #[must_use]
    pub const fn with_pgtt(mut self, pgtt: Pgtt) -> Self {
        self.q0 = (self.q0 & !(0x7 << 6)) | (((pgtt.bits() & 0x7) as u64) << 6);
        self
    }

    /// Page-table pointer (bits 63:12).
    ///
    /// Depending on `PGTT` this addresses the first-stage table
    /// (FSPTPTR), the second-stage table (SSPTPTR/SLPTPTR) or the
    /// nested-table root; hardware picks the interpretation.
    #[must_use]
    pub const fn page_table_ptr(&self) -> u64 {
        self.q0 & !0xfff
    }

    /// Set the page-table pointer.
    #[must_use]
    pub const fn with_page_table_ptr(mut self, addr: u64) -> Self {
        self.q0 = (self.q0 & 0xfff) | (addr & !0xfff);
        self
    }

    /// Domain identifier (entry bits 79:64, qword 1 bits 15:0).
    #[must_use]
    pub const fn domain_id(&self) -> u16 {
        self.q1 as u16
    }

    /// Set the domain identifier.
    #[must_use]
    pub const fn with_domain_id(mut self, did: u16) -> Self {
        self.q1 = (self.q1 & !0xffff) | did as u64;
        self
    }

    /// Page-snoop (PGSNP, qword 1 bit 24).
    #[must_use]
    pub const fn page_snoop(&self) -> bool {
        self.q1 & (1 << 24) != 0
    }

    /// Cache-disable (CD, qword 1 bit 25).
    #[must_use]
    pub const fn cache_disable(&self) -> bool {
        self.q1 & (1 << 25) != 0
    }

    /// Supervisor requests enable (SRE, qword 2 bit 0).
    #[must_use]
    pub const fn supervisor_requests(&self) -> bool {
        self.q2 & 1 != 0
    }

    /// Set supervisor requests enable.
    #[must_use]
    pub const fn with_supervisor_requests(mut self, en: bool) -> Self {
        self.q2 = (self.q2 & !1) | (en as u8) as u64;
        self
    }

    /// First-level paging mode (FLPM, qword 2 bits 3:2).
    #[must_use]
    pub const fn flpm(&self) -> Flpm {
        Flpm::from_bits(extract_bits(self.q2, 3, 2) as u8)
    }

    /// Set the first-level paging mode.
    #[must_use]
    pub const fn with_flpm(mut self, flpm: Flpm) -> Self {
        self.q2 = (self.q2 & !(0x3 << 2)) | (((flpm.bits() & 0x3) as u64) << 2);
        self
    }

    /// Write-protect enable (WPE, qword 2 bit 4) for supervisor requests.
    #[must_use]
    pub const fn write_protect_enable(&self) -> bool {
        self.q2 & (1 << 4) != 0
    }

    /// Extended-accessed-flag enable (EAFE, qword 2 bit 7).
    #[must_use]
    pub const fn ext_accessed_flag(&self) -> bool {
        self.q2 & (1 << 7) != 0
    }

    /// HPT size (entry bits 257:256, `hpt[1]` bits 1:0).
    #[must_use]
    pub const fn hpt_size(&self) -> u8 {
        extract_bits(self.hpt[1], 1, 0) as u8
    }

    /// HPT domain identifier (entry bits 335:320, `hpt[2]` bits 15:0).
    #[must_use]
    pub const fn hpt_domain_id(&self) -> u16 {
        self.hpt[2] as u16
    }

    /// HPT root pointer as raw `{hpt[3], hpt[2] bits 11:0}` pair
    /// (entry bits `(HAW+255):256`); the caller combines the chunks
    /// according to the platform HAW.
    #[must_use]
    pub const fn hpt_root_raw(&self) -> (u64, u64) {
        (self.hpt[3], self.hpt[2] & 0xfff)
    }

    /// Raw 64 bytes, little-endian, ready to store in the PASID table.
    #[must_use]
    pub fn into_bytes(self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..8].copy_from_slice(&self.q0.to_le_bytes());
        out[8..16].copy_from_slice(&self.q1.to_le_bytes());
        out[16..24].copy_from_slice(&self.q2.to_le_bytes());
        out[24..32].copy_from_slice(&self.q3.to_le_bytes());
        for (i, q) in self.hpt.iter().enumerate() {
            out[32 + i * 8..40 + i * 8].copy_from_slice(&q.to_le_bytes());
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Raw overlay helpers
// ---------------------------------------------------------------------------

/// Interpret `bytes` as a legacy root table entry.
///
/// Returns `None` when `bytes` is shorter than the entry.
#[must_use]
pub fn root_entry(bytes: &[u8]) -> Option<&RootEntry> {
    RootEntry::ref_from_bytes(bytes).ok()
}

/// Interpret `bytes` as a legacy context entry.
#[must_use]
pub fn context_entry(bytes: &[u8]) -> Option<&ContextEntry> {
    ContextEntry::ref_from_bytes(bytes).ok()
}

/// Interpret `bytes` as a scalable context entry.
#[must_use]
pub fn scalable_context_entry(bytes: &[u8]) -> Option<&ScalableContextEntry> {
    ScalableContextEntry::ref_from_bytes(bytes).ok()
}

/// Interpret `bytes` as a PASID table entry.
#[must_use]
pub fn pasid_table_entry(bytes: &[u8]) -> Option<&PasidTableEntry> {
    PasidTableEntry::ref_from_bytes(bytes).ok()
}

/// Number of entries of a given size that fit in a 4 KiB page.
#[must_use]
pub const fn entries_per_page(entry_size: usize) -> usize {
    4096 / entry_size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_context_roundtrip() {
        let ce = ContextEntry::new()
            .with_present(true)
            .with_domain_id(0x1234)
            .with_address_width(AddrWidth::Agaw48)
            .with_second_stage_ptr(0xdead_beef_f000)
            .with_translation_type(TransType::SecondStage);
        assert!(ce.present());
        assert_eq!(ce.domain_id(), 0x1234);
        assert_eq!(ce.second_stage_ptr(), 0xdead_beef_f000);
        assert_eq!(ce.address_width(), AddrWidth::Agaw48);
        // Entry bits 87:72 hold DID: q1 bytes 1..2.
        let raw = ce.into_bytes();
        assert_eq!(raw[0] & 1, 1);
        assert_eq!(u16::from_le_bytes([raw[9], raw[10]]), 0x1234);
    }

    #[test]
    fn pasid_entry_layout() {
        let pe = PasidTableEntry::new()
            .with_present(true)
            .with_pgtt(Pgtt::FirstStageOnly)
            .with_page_table_ptr(0x1234_5000)
            .with_domain_id(7)
            .with_flpm(Flpm::FiveLevel)
            .with_supervisor_requests(true);
        assert!(pe.present());
        assert_eq!(pe.pgtt(), Pgtt::FirstStageOnly);
        assert_eq!(pe.page_table_ptr(), 0x1234_5000);
        assert_eq!(pe.domain_id(), 7);
        assert_eq!(pe.flpm(), Flpm::FiveLevel);
        assert!(pe.supervisor_requests());
        // PGTT at bits 8:6.
        assert_eq!(extract_bits(pe.q0, 8, 6), 1);
        // DID at q1 bits 15:0.
        assert_eq!(pe.q1 & 0xffff, 7);
    }

    #[test]
    fn scalable_context_layout() {
        let ce = ScalableContextEntry::new()
            .with_present(true)
            .with_pasid_dir_ptr(0xabc000)
            .with_pasid_dir_size(1)
            .with_rid_pasid(0x1234)
            .with_rid_priv(true);
        assert!(ce.present());
        assert_eq!(ce.pasid_dir_ptr(), 0xabc000);
        assert_eq!(ce.pasid_dir_size(), 1);
        assert_eq!(ce.rid_pasid(), 0x1234);
        assert!(ce.rid_priv());
    }
}
