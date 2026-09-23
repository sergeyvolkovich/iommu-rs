//! Fault recording registers (section 10.4.14) and fault reason codes.
//!
//! Non-recoverable faults are logged into 128-bit fault recording
//! registers located at `CAP.FRO * 16` (see [`crate::regs::fault_rec_offset`]).
//! Recoverable faults (page requests) use the PRQ interface instead.
//!
//! ```
//! use intel_iommu::fault::{FaultRecord, FaultReason};
//!
//! let fr = FaultRecord::new()
//!     .with_source_id(0x0bad)
//!     .with_reason(FaultReason::PagingEntryRsvd)
//!     .with_fault_info(0x1234_5000)
//!     .with_fault(true);
//!
//! let raw: [u64; 2] = fr.words();
//! assert_eq!(raw[1] & 0xffff, 0x0bad);    // SID (bits 79:64)
//! assert_eq!((raw[1] >> 32) & 0xff, 0x06); // FR (bits 103:96)
//!
//! let back = FaultRecord::from_words(raw[0], raw[1]);
//! assert_eq!(back.reason(), FaultReason::PagingEntryRsvd);
//! assert!(back.fault());
//! ```

use crate::bits::extract_bits;
use core::fmt;

/// Fault reason (`FR`, bits 103:96) — the canonical non-recoverable fault
/// conditions (spec table 24). The list keeps the numeric codes of the
/// specification; variants marked `(5.20)` were introduced by recent
/// revisions.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
#[non_exhaustive]
pub enum FaultReason {
    /// `00h` default — no fault / unspecified.
    #[default]
    NoFault = 0x00,
    /// `01h` — root entry present bit 0.
    RootEntryPresent = 0x01,
    /// `02h` — context entry present bit 0.
    ContextEntryPresent = 0x02,
    /// `03h` — context entry hardware-implemented reserved bits.
    ContextEntryRsvd = 0x03,
    /// `04h` — translation-type in present context-entry unsupported.
    ContextEntryTt = 0x04,
    /// `05h` — second-level paging-entry present bit 0.
    PagingEntryPresent = 0x05,
    /// `06h` — non-zero reserved bits in second-level paging entry.
    PagingEntryRsvd = 0x06,
    /// `07h` — DMA request blocked (destination outside AGAW, write to
    /// read-only region etc.).
    AccessBlocked = 0x07,
    /// `10h` slot — `50h` PASID directory entry access failure.
    PasidDirAccess = 0x50,
    /// `11h` — PASID directory entry present bit 0.
    PasidDirPresent = 0x51,
    /// `12h` — PASID table entry access failure.
    PasidTableAccess = 0x58,
    /// `13h` — PASID table entry present bit 0.
    PasidTablePresent = 0x59,
    /// `14h` — PASID table entry invalid (reserved bits set).
    PasidTableInvalid = 0x5b,
    /// `20h` — one or more reserved fields set in interrupt remapping request.
    IrRequestRsvd = 0x20,
    /// `21h` — interrupt remapping index beyond table size.
    IrIndexOver = 0x21,
    /// `22h` — present bit not set in IRTE.
    IrEntryPresent = 0x22,
    /// `23h` — invalid interrupt remapping table address.
    IrRootInvalid = 0x23,
    /// `24h` — reserved bits in present IRTE.
    IrteRsvd = 0x24,
    /// `25h` — compatible format interrupt request while IR disabled.
    IrRequestCompat = 0x25,
    /// `26h` — blocking of interrupt requests due to invalid SID.
    IrSourceId = 0x26,
    /// `31h` — invalid translation table mode in RTADDR.
    RtaddrInvalidTtm = 0x31,
    /// `47h` — scalable context entry present bit 0 (SCT.8).
    SmContextEntryPresent = 0x47,
    /// `70h` — first-stage paging entry access failure.
    FsPagingEntryAccess = 0x70,
    /// `71h` — first-stage paging entry present bit 0.
    FsPagingEntryPresent = 0x71,
    /// `72h` — reserved bits set in present first-stage paging entry.
    FsPagingEntryRsvd = 0x72,
    /// `73h` — invalid FSPTPTR in PASID table entry.
    FsptptrInvalid = 0x73,
    /// `80h` — first-stage input address not canonical (SNG.1).
    FsNonCanonical = 0x80,
    /// `81h` — privilege violation on first-stage access (SNG.2).
    FsPrivilege = 0x81,
    /// `85h` — write access without write permission (SM.3).
    SmWrite = 0x85,
    /// `87h` — output address in interrupt address range (scalable).
    SmInterruptAddr = 0x87,
    /// Any other / vendor-specific value.
    Other(u8),
}

impl FaultReason {
    /// Build from the raw 8-bit field.
    #[must_use]
    pub const fn from_bits(v: u8) -> Self {
        match v {
            0x00 => FaultReason::NoFault,
            0x01 => FaultReason::RootEntryPresent,
            0x02 => FaultReason::ContextEntryPresent,
            0x03 => FaultReason::ContextEntryRsvd,
            0x04 => FaultReason::ContextEntryTt,
            0x05 => FaultReason::PagingEntryPresent,
            0x06 => FaultReason::PagingEntryRsvd,
            0x07 => FaultReason::AccessBlocked,
            0x50 => FaultReason::PasidDirAccess,
            0x51 => FaultReason::PasidDirPresent,
            0x58 => FaultReason::PasidTableAccess,
            0x59 => FaultReason::PasidTablePresent,
            0x5b => FaultReason::PasidTableInvalid,
            0x20 => FaultReason::IrRequestRsvd,
            0x21 => FaultReason::IrIndexOver,
            0x22 => FaultReason::IrEntryPresent,
            0x23 => FaultReason::IrRootInvalid,
            0x24 => FaultReason::IrteRsvd,
            0x25 => FaultReason::IrRequestCompat,
            0x26 => FaultReason::IrSourceId,
            0x31 => FaultReason::RtaddrInvalidTtm,
            0x47 => FaultReason::SmContextEntryPresent,
            0x70 => FaultReason::FsPagingEntryAccess,
            0x71 => FaultReason::FsPagingEntryPresent,
            0x72 => FaultReason::FsPagingEntryRsvd,
            0x73 => FaultReason::FsptptrInvalid,
            0x80 => FaultReason::FsNonCanonical,
            0x81 => FaultReason::FsPrivilege,
            0x85 => FaultReason::SmWrite,
            0x87 => FaultReason::SmInterruptAddr,
            other => FaultReason::Other(other),
        }
    }

    /// Raw 8-bit code.
    #[must_use]
    pub const fn bits(self) -> u8 {
        // A full match instead of `self as u8`: the enum carries a data
        // variant, so primitive casts are not permitted.
        match self {
            FaultReason::NoFault => 0x00,
            FaultReason::RootEntryPresent => 0x01,
            FaultReason::ContextEntryPresent => 0x02,
            FaultReason::ContextEntryRsvd => 0x03,
            FaultReason::ContextEntryTt => 0x04,
            FaultReason::PagingEntryPresent => 0x05,
            FaultReason::PagingEntryRsvd => 0x06,
            FaultReason::AccessBlocked => 0x07,
            FaultReason::PasidDirAccess => 0x50,
            FaultReason::PasidDirPresent => 0x51,
            FaultReason::PasidTableAccess => 0x58,
            FaultReason::PasidTablePresent => 0x59,
            FaultReason::PasidTableInvalid => 0x5b,
            FaultReason::IrRequestRsvd => 0x20,
            FaultReason::IrIndexOver => 0x21,
            FaultReason::IrEntryPresent => 0x22,
            FaultReason::IrRootInvalid => 0x23,
            FaultReason::IrteRsvd => 0x24,
            FaultReason::IrRequestCompat => 0x25,
            FaultReason::IrSourceId => 0x26,
            FaultReason::RtaddrInvalidTtm => 0x31,
            FaultReason::SmContextEntryPresent => 0x47,
            FaultReason::FsPagingEntryAccess => 0x70,
            FaultReason::FsPagingEntryPresent => 0x71,
            FaultReason::FsPagingEntryRsvd => 0x72,
            FaultReason::FsptptrInvalid => 0x73,
            FaultReason::FsNonCanonical => 0x80,
            FaultReason::FsPrivilege => 0x81,
            FaultReason::SmWrite => 0x85,
            FaultReason::SmInterruptAddr => 0x87,
            FaultReason::Other(v) => v,
        }
    }
}

impl fmt::Display for FaultReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FaultReason::NoFault => write!(f, "no fault"),
            FaultReason::RootEntryPresent => write!(f, "root entry not present"),
            FaultReason::ContextEntryPresent => write!(f, "context entry not present"),
            FaultReason::ContextEntryRsvd => write!(f, "context entry reserved bits"),
            FaultReason::ContextEntryTt => write!(f, "unsupported translation type"),
            FaultReason::PagingEntryPresent => write!(f, "paging entry not present"),
            FaultReason::PagingEntryRsvd => write!(f, "paging entry reserved bits"),
            FaultReason::AccessBlocked => write!(f, "DMA access blocked"),
            FaultReason::PasidDirAccess => write!(f, "PASID directory access failure"),
            FaultReason::PasidDirPresent => write!(f, "PASID directory entry not present"),
            FaultReason::PasidTableAccess => write!(f, "PASID table access failure"),
            FaultReason::PasidTablePresent => write!(f, "PASID table entry not present"),
            FaultReason::PasidTableInvalid => write!(f, "PASID table entry invalid"),
            FaultReason::IrRequestRsvd => write!(f, "IR request reserved fields"),
            FaultReason::IrIndexOver => write!(f, "IR index out of range"),
            FaultReason::IrEntryPresent => write!(f, "IRTE not present"),
            FaultReason::IrRootInvalid => write!(f, "invalid IR table address"),
            FaultReason::IrteRsvd => write!(f, "IRTE reserved bits"),
            FaultReason::IrRequestCompat => write!(f, "compat interrupt while IR disabled"),
            FaultReason::IrSourceId => write!(f, "interrupt source-id invalid"),
            FaultReason::RtaddrInvalidTtm => write!(f, "invalid TTM in RTADDR"),
            FaultReason::SmContextEntryPresent => write!(f, "scalable context entry not present"),
            FaultReason::FsPagingEntryAccess => write!(f, "first-stage entry access failure"),
            FaultReason::FsPagingEntryPresent => write!(f, "first-stage entry not present"),
            FaultReason::FsPagingEntryRsvd => write!(f, "first-stage entry reserved bits"),
            FaultReason::FsptptrInvalid => write!(f, "invalid FSPTPTR"),
            FaultReason::FsNonCanonical => write!(f, "non-canonical first-stage address"),
            FaultReason::FsPrivilege => write!(f, "first-stage privilege violation"),
            FaultReason::SmWrite => write!(f, "write without permission"),
            FaultReason::SmInterruptAddr => write!(f, "output in interrupt address range"),
            FaultReason::Other(v) => write!(f, "fault reason 0x{v:02x}"),
        }
    }
}

/// Address type (`AT`, bits 125:124 of the fault record).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum AddrType {
    /// Default (untranslated / according to request) (00b).
    #[default]
    Default,
    /// Translation request (01b).
    TranslationRequest,
    /// Translated request (10b).
    Translated,
    /// Reserved (11b).
    Reserved,
}

impl AddrType {
    /// Decode from the raw 2-bit field.
    #[must_use]
    pub const fn from_bits(v: u8) -> Self {
        match v & 0x3 {
            0 => AddrType::Default,
            1 => AddrType::TranslationRequest,
            2 => AddrType::Translated,
            _ => AddrType::Reserved,
        }
    }

    /// Raw 2-bit encoding.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            AddrType::Default => 0,
            AddrType::TranslationRequest => 1,
            AddrType::Translated => 2,
            AddrType::Reserved => 3,
        }
    }
}

/// One 128-bit fault recording register (section 10.4.14, FRCD_REG).
///
/// | Bits    | Field |
/// |---------|-------|
/// | 127     | F (fault) |
/// | 126     | T1 (type bit 1) |
/// | 125:124 | AT (address type) |
/// | 123:104 | PV (PASID value) |
/// | 103:96  | FR (fault reason) |
/// | 95      | PP (PASID present) |
/// | 94      | PRIV (privilege mode requested) |
/// | 93      | EXEC (execute requested) |
/// | 92      | T2 (type bit 2) |
/// | 91:80   | reserved |
/// | 79:64   | SID (source identifier) |
/// | 63:12   | FI (fault info) |
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, zerocopy::FromBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
#[repr(C)]
pub struct FaultRecord {
    /// Low qword: fault info (63:12).
    pub low: u64,
    /// High qword: SID, FR, PP, PRIV, EXEC, T2, AT, T1, F.
    pub high: u64,
}

impl FaultRecord {
    /// Start building a record with all fields zeroed.
    #[must_use]
    pub const fn new() -> Self {
        FaultRecord { low: 0, high: 0 }
    }

    /// Fault flag (bit 127): the record holds a fault when set.
    #[must_use]
    pub const fn fault(&self) -> bool {
        self.high & (1 << 63) != 0
    }

    /// Set the fault flag.
    #[must_use]
    pub const fn with_fault(mut self, f: bool) -> Self {
        self.high = (self.high & !(1 << 63)) | (((f as u8) as u64) << 63);
        self
    }

    /// Fault reason.
    #[must_use]
    pub const fn reason(&self) -> FaultReason {
        FaultReason::from_bits(extract_bits(self.high, 39, 32) as u8)
    }

    /// Set the fault reason.
    #[must_use]
    pub const fn with_reason(mut self, fr: FaultReason) -> Self {
        let bits = (fr.bits()) as u64;
        self.high = (self.high & !(0xff << 32)) | (bits << 32);
        self
    }

    /// Source identifier (record bits 79:64 = high qword bits 15:0).
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

    /// Fault info (address or data associated with the fault).
    #[must_use]
    pub const fn fault_info(&self) -> u64 {
        self.low & !0xfff
    }

    /// Set the fault info.
    #[must_use]
    pub const fn with_fault_info(mut self, fi: u64) -> Self {
        self.low = (self.low & 0xfff) | (fi & !0xfff);
        self
    }

    /// PASID present flag (PP).
    #[must_use]
    pub const fn pasid_present(&self) -> bool {
        self.high & (1 << 31) != 0
    }

    /// PASID value (when `pasid_present`).
    #[must_use]
    pub const fn pasid(&self) -> u32 {
        extract_bits(self.high, 59, 40) as u32
    }

    /// Set PASID + present flag.
    #[must_use]
    pub const fn with_pasid(mut self, pasid: u32) -> Self {
        self.high = (self.high & !(0xf_ffff << 40)) | (((pasid & 0xf_ffff) as u64) << 40);
        self.high |= 1 << 31;
        self
    }

    /// Privilege-mode requested (PRIV).
    #[must_use]
    pub const fn privilege_requested(&self) -> bool {
        self.high & (1 << 30) != 0
    }

    /// Execute requested (EXEC).
    #[must_use]
    pub const fn execute_requested(&self) -> bool {
        self.high & (1 << 29) != 0
    }

    /// Address type.
    #[must_use]
    pub const fn addr_type(&self) -> AddrType {
        AddrType::from_bits(extract_bits(self.high, 61, 60) as u8)
    }

    /// Set the address type.
    #[must_use]
    pub const fn with_addr_type(mut self, at: AddrType) -> Self {
        let bits = (at.bits()) as u64;
        self.high = (self.high & !(0x3 << 60)) | (bits << 60);
        self
    }

    /// Raw words (low, high).
    #[must_use]
    pub const fn words(&self) -> [u64; 2] {
        [self.low, self.high]
    }

    /// Decode from raw words.
    #[must_use]
    pub const fn from_words(low: u64, high: u64) -> Self {
        FaultRecord { low, high }
    }
}
