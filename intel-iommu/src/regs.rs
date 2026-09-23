//! VT-d MMIO register map and capability registers.
//!
//! Register offsets follow section 11.4 of the VT-d specification. The
//! constants mirror the specification numbering so they can be cross-checked
//! against table 11-1 directly. [`Cap`] and [`Ecap`] decode the two 64-bit
//! capability registers; the remaining helpers build/decode command and
//! status register words without requiring a live MMIO mapping.
//!
//! For drivers that want a typed view of the register block, this module
//! also exposes a [`tock_registers`] description of the fixed registers
//! (offsets 000h–0B8h). Registers whose location depends on capability
//! fields (IOTLB at `ECAP.IRO`, fault records at `CAP.FRO`, performance
//! monitoring) are indexed dynamically at run time — see [`iotlb_offset`]
//! and [`fault_rec_offset`].

use crate::bits::extract_bits;
use bitflags::bitflags;
use tock_registers::registers::ReadWrite;
use tock_registers::{register_bitfields, register_structs};

// ---------------------------------------------------------------------------
// Register offsets (spec table 11-1)
// ---------------------------------------------------------------------------

/// Version register.
pub const VER: u64 = 0x000;
/// Capability register.
pub const CAP: u64 = 0x008;
/// Extended capability register.
pub const ECAP: u64 = 0x010;
/// Global command register.
pub const GCMD: u64 = 0x018;
/// Global status register.
pub const GSTS: u64 = 0x01c;
/// Root table address register.
pub const RTADDR: u64 = 0x020;
/// Context command register.
pub const CCMD: u64 = 0x028;
/// Fault status register.
pub const FSTS: u64 = 0x034;
/// Fault event control register.
pub const FECTL: u64 = 0x038;
/// Fault event data register.
pub const FEDATA: u64 = 0x03c;
/// Fault event address register.
pub const FEADDR: u64 = 0x040;
/// Fault event upper address register.
pub const FEUADDR: u64 = 0x044;
/// Protected memory enable register.
pub const PMEN: u64 = 0x064;
/// Protected low memory base register.
pub const PLMBAS: u64 = 0x068;
/// Protected low memory limit register.
pub const PLMLIMIT: u64 = 0x06c;
/// Protected high memory base register.
pub const PHMBAS: u64 = 0x070;
/// Protected high memory limit register.
pub const PHMLIMIT: u64 = 0x078;
/// Invalidation queue head register.
pub const IQH: u64 = 0x080;
/// Invalidation queue tail register.
pub const IQT: u64 = 0x088;
/// Invalidation queue address register.
pub const IQA: u64 = 0x090;
/// Invalidation completion status register.
pub const ICS: u64 = 0x09c;
/// Invalidation completion event control register.
pub const IECTL: u64 = 0x0a0;
/// Invalidation completion event data register.
pub const IEDATA: u64 = 0x0a4;
/// Invalidation completion event address register.
pub const IEADDR: u64 = 0x0a8;
/// Invalidation completion event upper address register.
pub const IEUADDR: u64 = 0x0ac;
/// Invalidation queue error record register.
pub const IQERCD: u64 = 0x0b0;
/// Interrupt remapping table address register.
pub const IRTA: u64 = 0x0b8;
/// Page request queue head register.
pub const PQH: u64 = 0x0c0;
/// Page request queue tail register.
pub const PQT: u64 = 0x0c8;
/// Page request queue address register.
pub const PQA: u64 = 0x0d0;
/// Page request status register.
pub const PQS: u64 = 0x0dc;
/// Page request event control register.
pub const PECTL: u64 = 0x0e0;
/// Page request event data register.
pub const PEDATA: u64 = 0x0e4;
/// Page request event address register.
pub const PEADDR: u64 = 0x0e8;
/// Page request event upper address register.
pub const PEUADDR: u64 = 0x0ec;
/// MTRR capability register.
pub const MTRRCAP: u64 = 0x100;
/// MTRR default type register.
pub const MTRRDEF: u64 = 0x108;
/// First variable-range MTRR base register.
pub const MTRR_PHYSBASE0: u64 = 0x180;
/// First variable-range MTRR mask register.
pub const MTRR_PHYSMASK0: u64 = 0x188;
/// Performance monitoring capability register.
pub const PERFCAP: u64 = 0x300;
/// Enhanced command register.
pub const ECMD: u64 = 0x400;
/// Enhanced command operand offset register.
pub const ECEO: u64 = 0x408;
/// Enhanced command response register.
pub const ECRSP: u64 = 0x410;
/// Enhanced command capability register.
pub const ECCAP: u64 = 0x430;
/// Virtual command register.
pub const VCMD: u64 = 0x440;
/// Virtual command extended operand register.
pub const VCEO: u64 = 0x448;
/// Virtual command response register.
pub const VCRSP: u64 = 0x450;
/// Virtual command capability register.
pub const VCCAP: u64 = 0x458;

/// Size in bytes of one queue entry (invalidation or page request).
pub const QUEUE_ENTRY_SHIFT: u32 = 4;

/// Address of the IOTLB invalidation register for a given `ECAP` value.
///
/// The IVA (invalidation address) register sits at `ECAP.IRO * 16`; the
/// IOTLB invalidation control register is at `IVA + 8`.
#[inline]
#[must_use]
pub fn iotlb_offset(ecap: Ecap) -> (u64, u64) {
    let iva = extract_bits(ecap.0, 17, 8) << 4;
    (iva, iva + 8)
}

/// Address of fault-recording register `n` for a given `CAP` value.
#[inline]
#[must_use]
pub fn fault_rec_offset(cap: Cap, n: u16) -> u64 {
    (extract_bits(cap.0, 33, 24) << 4) + (n as u64) * 16
}

// ---------------------------------------------------------------------------
// Capability register (spec 11.4.2, figure 11-2)
// ---------------------------------------------------------------------------

/// Decoded Capability Register (`CAP_REG`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Cap(pub u64);

impl Cap {
    /// Wrap a raw register value.
    #[inline]
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Number of domains: `2^(ND*2 + 4)` (4..=16 bit domain-ids).
    #[inline]
    #[must_use]
    pub const fn domain_ids(&self) -> u32 {
        1u32 << (4 + 2 * (extract_bits(self.0, 2, 0) as u32))
    }

    /// Required write-buffer flushing (RWBF).
    #[inline]
    #[must_use]
    pub const fn rwbf(&self) -> bool {
        extract_bits(self.0, 4, 4) != 0
    }

    /// Protected low-memory region supported (PLMR).
    #[inline]
    #[must_use]
    pub const fn plmr(&self) -> bool {
        extract_bits(self.0, 5, 5) != 0
    }

    /// Protected high-memory region supported (PHMR).
    #[inline]
    #[must_use]
    pub const fn phmr(&self) -> bool {
        extract_bits(self.0, 6, 6) != 0
    }

    /// Caching mode (CM).
    #[inline]
    #[must_use]
    pub const fn caching_mode(&self) -> bool {
        extract_bits(self.0, 7, 7) != 0
    }

    /// Supported adjusted guest address widths (SAGAW bitfield).
    ///
    /// Bit 1 = 39-bit (3-level), bit 2 = 48-bit (4-level), bit 3 = 57-bit
    /// (5-level).
    #[inline]
    #[must_use]
    pub const fn sagaw(&self) -> u8 {
        extract_bits(self.0, 12, 8) as u8
    }

    /// Maximum guest address width in bits (MGAW).
    #[inline]
    #[must_use]
    pub const fn mgaw(&self) -> u32 {
        extract_bits(self.0, 21, 16) as u32 + 1
    }

    /// Zero-length read support (ZLR).
    #[inline]
    #[must_use]
    pub const fn zlr(&self) -> bool {
        extract_bits(self.0, 22, 22) != 0
    }

    /// Deprecated field (must read 0).
    #[inline]
    #[must_use]
    pub const fn dep(&self) -> bool {
        extract_bits(self.0, 23, 23) != 0
    }

    /// Offset (in units of 16 bytes) of the first fault recording register.
    #[inline]
    #[must_use]
    pub const fn fault_rec_offset_raw(&self) -> u16 {
        extract_bits(self.0, 33, 24) as u16
    }

    /// Second-stage large page support (`SSLPS`): bit0 = 2 MiB, bit1 = 1 GiB.
    #[inline]
    #[must_use]
    pub const fn sslps(&self) -> u8 {
        extract_bits(self.0, 37, 34) as u8
    }

    /// Page-selective IOTLB invalidation support (PSI).
    #[inline]
    #[must_use]
    pub const fn page_selective_inval(&self) -> bool {
        extract_bits(self.0, 39, 39) != 0
    }

    /// Number of fault recording registers (NFR = value + 1).
    #[inline]
    #[must_use]
    pub const fn num_fault_regs(&self) -> u16 {
        extract_bits(self.0, 47, 40) as u16 + 1
    }

    /// Maximum address mask value for page-selective invalidations (MAMV).
    #[inline]
    #[must_use]
    pub const fn max_amask_value(&self) -> u8 {
        extract_bits(self.0, 53, 48) as u8
    }

    /// Write draining on IOTLB invalidation (DWD/DRD).
    #[inline]
    #[must_use]
    pub const fn write_drain(&self) -> bool {
        extract_bits(self.0, 54, 54) != 0
    }

    /// Read draining on IOTLB invalidation (DRD).
    #[inline]
    #[must_use]
    pub const fn read_drain(&self) -> bool {
        extract_bits(self.0, 55, 55) != 0
    }

    /// First-stage 1-GiB page support (FS1GP).
    #[inline]
    #[must_use]
    pub const fn fs_1g_pages(&self) -> bool {
        extract_bits(self.0, 56, 56) != 0
    }

    /// Posted interrupt support (PI).
    #[inline]
    #[must_use]
    pub const fn posted_interrupts(&self) -> bool {
        extract_bits(self.0, 59, 59) != 0
    }

    /// First-stage 5-level paging support (FS5LP).
    #[inline]
    #[must_use]
    pub const fn fs_5level(&self) -> bool {
        extract_bits(self.0, 60, 60) != 0
    }

    /// Enhanced command interface support (ECMDS).
    #[inline]
    #[must_use]
    pub const fn enhanced_commands(&self) -> bool {
        extract_bits(self.0, 61, 61) != 0
    }

    /// Set-interrupt-remap-table-pointer cache invalidation (ESIRTPS).
    #[inline]
    #[must_use]
    pub const fn esirtps(&self) -> bool {
        extract_bits(self.0, 62, 62) != 0
    }

    /// Set-root-table-pointer cache invalidation (ESRTPS).
    #[inline]
    #[must_use]
    pub const fn esrtps(&self) -> bool {
        extract_bits(self.0, 63, 63) != 0
    }
}

// ---------------------------------------------------------------------------
// Extended capability register (spec 11.4.3, figure 11-3)
// ---------------------------------------------------------------------------

/// Decoded Extended Capability Register (`ECAP_REG`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Ecap(pub u64);

impl Ecap {
    /// Wrap a raw register value.
    #[inline]
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Page-walk coherency (C).
    #[inline]
    #[must_use]
    pub const fn coherent(&self) -> bool {
        extract_bits(self.0, 0, 0) != 0
    }

    /// Queued invalidation support (QI).
    #[inline]
    #[must_use]
    pub const fn queued_inval(&self) -> bool {
        extract_bits(self.0, 1, 1) != 0
    }

    /// Device-TLB support (DT).
    #[inline]
    #[must_use]
    pub const fn dev_tlb(&self) -> bool {
        extract_bits(self.0, 2, 2) != 0
    }

    /// Interrupt remapping support (IR).
    #[inline]
    #[must_use]
    pub const fn intr_remap(&self) -> bool {
        extract_bits(self.0, 3, 3) != 0
    }

    /// Extended interrupt mode supported (EIM).
    #[inline]
    #[must_use]
    pub const fn extended_intr_mode(&self) -> bool {
        extract_bits(self.0, 4, 4) != 0
    }

    /// Pass-through translation support (PT).
    #[inline]
    #[must_use]
    pub const fn pass_through(&self) -> bool {
        extract_bits(self.0, 6, 6) != 0
    }

    /// Snoop control support (SC).
    #[inline]
    #[must_use]
    pub const fn snoop_control(&self) -> bool {
        extract_bits(self.0, 7, 7) != 0
    }

    /// IOTLB register offset in units of 16 bytes (IRO).
    #[inline]
    #[must_use]
    pub const fn iotlb_offset_raw(&self) -> u16 {
        extract_bits(self.0, 17, 8) as u16
    }

    /// Maximum handle mask value for Device-TLB invalidations (MHMV).
    #[inline]
    #[must_use]
    pub const fn max_handle_mask(&self) -> u8 {
        extract_bits(self.0, 23, 20) as u8
    }

    /// Memory type support (MTS).
    #[inline]
    #[must_use]
    pub const fn memory_type(&self) -> bool {
        extract_bits(self.0, 25, 25) != 0
    }

    /// Nested translation support (NEST).
    #[inline]
    #[must_use]
    pub const fn nested(&self) -> bool {
        extract_bits(self.0, 26, 26) != 0
    }

    /// Deferred invalidation support (DIS).
    #[inline]
    #[must_use]
    pub const fn deferred_inval(&self) -> bool {
        extract_bits(self.0, 27, 27) != 0
    }

    /// Page request support (PRS).
    #[inline]
    #[must_use]
    pub const fn page_requests(&self) -> bool {
        extract_bits(self.0, 29, 29) != 0
    }

    /// Execute request support (ERS).
    #[inline]
    #[must_use]
    pub const fn execute_requests(&self) -> bool {
        extract_bits(self.0, 30, 30) != 0
    }

    /// Supervisor request support (SRS).
    #[inline]
    #[must_use]
    pub const fn supervisor_requests(&self) -> bool {
        extract_bits(self.0, 31, 31) != 0
    }

    /// No-write flag support (NWFS).
    #[inline]
    #[must_use]
    pub const fn no_write_flag(&self) -> bool {
        extract_bits(self.0, 33, 33) != 0
    }

    /// Extended accessed flag support (EAFS).
    #[inline]
    #[must_use]
    pub const fn extended_accessed_flag(&self) -> bool {
        extract_bits(self.0, 34, 34) != 0
    }

    /// PASID size supported: `2^(PSS+1) - 1` is the largest PASID value.
    #[inline]
    #[must_use]
    pub const fn pasid_size(&self) -> u8 {
        extract_bits(self.0, 39, 35) as u8
    }

    /// PASID support (PASID).
    #[inline]
    #[must_use]
    pub const fn pasid(&self) -> bool {
        extract_bits(self.0, 40, 40) != 0
    }

    /// Device-TLB invalidation throttling (DIT).
    #[inline]
    #[must_use]
    pub const fn devtlb_inval_throttle(&self) -> bool {
        extract_bits(self.0, 41, 41) != 0
    }

    /// PASID-based Device-TLB support (PDS).
    #[inline]
    #[must_use]
    pub const fn pasid_devtlb(&self) -> bool {
        extract_bits(self.0, 42, 42) != 0
    }

    /// Scalable-mode translation support (SMTS).
    #[inline]
    #[must_use]
    pub const fn scalable_mode(&self) -> bool {
        extract_bits(self.0, 43, 43) != 0
    }

    /// Virtual command support (VCS).
    #[inline]
    #[must_use]
    pub const fn virtual_commands(&self) -> bool {
        extract_bits(self.0, 44, 44) != 0
    }

    /// Second-stage accessed/dirty flag support (SSADS).
    #[inline]
    #[must_use]
    pub const fn ss_accessed_dirty(&self) -> bool {
        extract_bits(self.0, 45, 45) != 0
    }

    /// Second-level (stage) translation support (SLTS).
    #[inline]
    #[must_use]
    pub const fn second_stage(&self) -> bool {
        extract_bits(self.0, 46, 46) != 0
    }

    /// First-level (stage) translation support (FLTS).
    #[inline]
    #[must_use]
    pub const fn first_stage(&self) -> bool {
        extract_bits(self.0, 47, 47) != 0
    }

    /// Scalable-mode page-walk coherency (SMPWCS).
    #[inline]
    #[must_use]
    pub const fn sm_page_walk_coherency(&self) -> bool {
        extract_bits(self.0, 48, 48) != 0
    }

    /// RID_PASID support (RPS).
    #[inline]
    #[must_use]
    pub const fn rid_pasid(&self) -> bool {
        extract_bits(self.0, 49, 49) != 0
    }

    /// TDX-connect support (TDXCS).
    #[inline]
    #[must_use]
    pub const fn tdx_connect(&self) -> bool {
        extract_bits(self.0, 50, 50) != 0
    }

    /// Performance monitoring support (PMS).
    #[inline]
    #[must_use]
    pub const fn perf_monitoring(&self) -> bool {
        extract_bits(self.0, 51, 51) != 0
    }

    /// Abort DMA mode support (ADMS).
    #[inline]
    #[must_use]
    pub const fn abort_dma_mode(&self) -> bool {
        extract_bits(self.0, 52, 52) != 0
    }

    /// RID_PRIV support (RPRIVS).
    #[inline]
    #[must_use]
    pub const fn rid_priv(&self) -> bool {
        extract_bits(self.0, 53, 53) != 0
    }

    /// Host permission table support (HPTS).
    #[inline]
    #[must_use]
    pub const fn host_permission_table(&self) -> bool {
        extract_bits(self.0, 55, 55) != 0
    }

    /// PASID in translated requests (PTRS).
    #[inline]
    #[must_use]
    pub const fn pasid_translated(&self) -> bool {
        extract_bits(self.0, 56, 56) != 0
    }

    /// Second-stage I/O read/write permission bits (SSIRWS).
    #[inline]
    #[must_use]
    pub const fn ss_io_rw_bits(&self) -> bool {
        extract_bits(self.0, 57, 57) != 0
    }

    /// Stop-marker support (SMS).
    #[inline]
    #[must_use]
    pub const fn stop_marker(&self) -> bool {
        extract_bits(self.0, 58, 58) != 0
    }

    /// HPT 1-GiB page support (HPT1GPS).
    #[inline]
    #[must_use]
    pub const fn hpt_1g_pages(&self) -> bool {
        extract_bits(self.0, 59, 59) != 0
    }

    /// RDT configuration support (RDTS).
    #[inline]
    #[must_use]
    pub const fn rdt_config(&self) -> bool {
        extract_bits(self.0, 60, 60) != 0
    }

    /// Extended interrupt mode required (EIMER).
    #[inline]
    #[must_use]
    pub const fn eim_required(&self) -> bool {
        extract_bits(self.0, 61, 61) != 0
    }

    /// Interrupt remapping required (IRREQ).
    #[inline]
    #[must_use]
    pub const fn ir_required(&self) -> bool {
        extract_bits(self.0, 62, 62) != 0
    }
}

// ---------------------------------------------------------------------------
// GCMD / GSTS (spec 11.4.4)
// ---------------------------------------------------------------------------

bitflags! {
    /// Global Command Register (`GCMD`) write bits.
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct Gcmd: u32 {
        /// Enable translation (TE).
        const ENABLE = 1 << 31;
        /// Set root table pointer (SRTP).
        const SRTP = 1 << 30;
        /// Set fault log (SFL).
        const SFL = 1 << 29;
        /// Write buffer flush (WBF).
        const WBF = 1 << 28;
        /// Enable ATS (EA).
        const EA = 1 << 27;
        /// Queued invalidation enable (QIE).
        const QIE = 1 << 26;
        /// Interrupt remapping enable (IRE).
        const IRE = 1 << 25;
        /// Set interrupt remap table pointer (SIRTP).
        const SIRTP = 1 << 24;
        /// Compatibility format interrupt (CFI).
        const CFI = 1 << 23;
    }
}

bitflags! {
    /// Global Status Register (`GSTS`) read bits.
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct Gsts: u32 {
        /// Translation enabled (TES).
        const TES = 1 << 31;
        /// Root table pointer set (RTPS).
        const RTPS = 1 << 30;
        /// Fault log enabled (FLS).
        const FLS = 1 << 29;
        /// Write buffer flushed (WBFS).
        const WBFS = 1 << 28;
        /// ATS enabled (EAS).
        const EAS = 1 << 27;
        /// Queued invalidation enabled (QIES).
        const QIES = 1 << 26;
        /// Interrupt remapping enabled (IRES).
        const IRES = 1 << 25;
        /// Interrupt remap table pointer set (IRTPS).
        const IRTPS = 1 << 24;
        /// Compatibility format interrupts pending (CFIS).
        const CFIS = 1 << 23;
    }
}

// ---------------------------------------------------------------------------
// Version register
// ---------------------------------------------------------------------------

/// Major/minor architecture version from the Version register.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Version {
    /// Major version.
    pub major: u8,
    /// Minor version.
    pub minor: u8,
}

impl Version {
    /// Decode a raw Version register value.
    #[inline]
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self {
            major: ((raw & 0xf0) >> 4) as u8,
            minor: (raw & 0x0f) as u8,
        }
    }
}

// ---------------------------------------------------------------------------
// Command/status register words
// ---------------------------------------------------------------------------

/// Root Table Address Register word (`RTADDR`).
///
/// * bits 63:12 — root-table base address
/// * bits 11:10 — translation table mode (TTM)
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Rtaddr(pub u64);

impl Rtaddr {
    /// Translation table mode.
    #[inline]
    #[must_use]
    pub const fn table_mode(&self) -> TableMode {
        match extract_bits(self.0, 11, 10) {
            0 => TableMode::Legacy,
            1 => TableMode::Scalable,
            2 => TableMode::AbortDma,
            _ => TableMode::Reserved,
        }
    }

    /// Root-table base address (bits 63:12 shifted into place).
    #[inline]
    #[must_use]
    pub const fn table_base(&self) -> u64 {
        extract_bits(self.0, 63, 12) << 12
    }
}

/// Translation Table Mode (TTM) encoding of `RTADDR_REG`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TableMode {
    /// Legacy 4-level root/context tables.
    Legacy,
    /// Scalable-mode root/context tables.
    Scalable,
    /// Abort DMA mode (all requests blocked).
    AbortDma,
    /// Reserved encoding.
    Reserved,
}

/// Context Command Register word (`CCMD`).
///
/// * bit 63 — ICC (initiate cache invalidation)
/// * bits 5:4 — CIRG (invalidation granularity)
/// * bits 49:32 — SID, bits 33:32 — FM, bits 23:8 — DID
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Ccmd(pub u64);

/// Context-cache invalidation granularity (`CIRG`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Cirg {
    /// Reserved encoding (00b).
    Reserved,
    /// Global invalidation (01b).
    Global,
    /// Domain-selective invalidation (10b).
    Domain,
    /// Device-selective invalidation (11b).
    Device,
}

impl Ccmd {
    /// Build a CCMD word.
    #[must_use]
    pub fn new(granularity: Cirg, did: u16, sid: u16, fm: u8) -> Self {
        let cirg = match granularity {
            Cirg::Reserved => 0u64,
            Cirg::Global => 1,
            Cirg::Domain => 2,
            Cirg::Device => 3,
        };
        let mut v = (cirg << 4) | ((did as u64) << 8) | ((sid as u64) << 32);
        v |= ((fm & 0x3) as u64) << 32; // FM lives at bits 33:32
        Ccmd(v)
    }

    /// Initiate-invalidation bit.
    #[inline]
    #[must_use]
    pub const fn initiate(&self) -> bool {
        extract_bits(self.0, 63, 63) != 0
    }

    /// Granularity.
    #[inline]
    #[must_use]
    pub const fn granularity(&self) -> Cirg {
        match extract_bits(self.0, 5, 4) {
            1 => Cirg::Global,
            2 => Cirg::Domain,
            3 => Cirg::Device,
            _ => Cirg::Reserved,
        }
    }

    /// Domain id.
    #[inline]
    #[must_use]
    pub const fn did(&self) -> u16 {
        extract_bits(self.0, 31, 8) as u16
    }

    /// Source id.
    #[inline]
    #[must_use]
    pub const fn sid(&self) -> u16 {
        extract_bits(self.0, 47, 32) as u16
    }

    /// Function mask.
    #[inline]
    #[must_use]
    pub const fn fm(&self) -> u8 {
        extract_bits(self.0, 33, 32) as u8
    }
}

/// Invalidation Queue Address Register word (`IQA`).
///
/// * bits 63:12 — queue base address
/// * bit 4 — DW (descriptor width: 0 = 128-bit, 1 = 256-bit)
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Iqa(pub u64);

impl Iqa {
    /// Build an IQA word from a 4 KiB-aligned base address and width flag.
    #[inline]
    #[must_use]
    pub const fn new(base: u64, wide: bool) -> Self {
        Self((base & !0xfff) | ((wide as u64) << 4))
    }

    /// Queue base address.
    #[inline]
    #[must_use]
    pub const fn base(&self) -> u64 {
        extract_bits(self.0, 63, 12) << 12
    }

    /// Descriptor width: `true` for 256-bit descriptors.
    #[inline]
    #[must_use]
    pub const fn wide_descriptors(&self) -> bool {
        extract_bits(self.0, 4, 4) != 0
    }
}

/// Interrupt Remapping Table Address Register word (`IRTA`).
///
/// * bits 63:12 — table base
/// * bits 15:14 — S (table size: `2^(S+1)` entries)
/// * bit 11 — EIME (x2APIC mode)
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Irta(pub u64);

impl Irta {
    /// Build an IRTA word.
    #[inline]
    #[must_use]
    pub const fn new(base: u64, size_order: u8, x2apic: bool) -> Self {
        Self(
            (base & !0xfff)
                | (((size_order & 0x3) as u64) << 14)
                | ((x2apic as u64) << 11),
        )
    }

    /// Table base address.
    #[inline]
    #[must_use]
    pub const fn base(&self) -> u64 {
        extract_bits(self.0, 63, 12) << 12
    }

    /// Table size order: the table holds `2^(S+1)` entries.
    #[inline]
    #[must_use]
    pub const fn size_order(&self) -> u8 {
        extract_bits(self.0, 15, 14) as u8
    }

    /// Extended interrupt mode enable (x2APIC destinations).
    #[inline]
    #[must_use]
    pub const fn eime(&self) -> bool {
        extract_bits(self.0, 11, 11) != 0
    }
}

// ---------------------------------------------------------------------------
// IOTLB invalidation registers (IVA_REG / IOTLB_REG at ECAP.IRO)
// ---------------------------------------------------------------------------

/// IOTLB Invalidation control word (`IOTLB_REG`, at IVA+8).
///
/// * bit 63 — IVT (invalidate)
/// * bits 61:60 — IIRG (granularity)
/// * bit 49 — drain reads, bit 48 — drain writes
/// * bits 47:32 — DID
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IotlbInval(pub u64);

/// IOTLB invalidation granularity (`IIRG`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Iirg {
    /// Reserved encoding (00b).
    Reserved,
    /// Global invalidation (01b).
    Global,
    /// Domain-selective invalidation (10b).
    Domain,
    /// Page-selective-within-domain (11b).
    Page,
}

impl IotlbInval {
    /// Build the control word.
    #[must_use]
    pub fn new(granularity: Iirg, did: u16, drain_reads: bool, drain_writes: bool) -> Self {
        let iirg = match granularity {
            Iirg::Reserved => 0u64,
            Iirg::Global => 1,
            Iirg::Domain => 2,
            Iirg::Page => 3,
        };
        let mut v = iirg << 60;
        if drain_reads {
            v |= 1 << 49;
        }
        if drain_writes {
            v |= 1 << 48;
        }
        v |= (did as u64) << 32;
        IotlbInval(v)
    }

    /// Initiate invalidation bit.
    #[inline]
    #[must_use]
    pub const fn initiate(&self) -> bool {
        extract_bits(self.0, 63, 63) != 0
    }

    /// Granularity.
    #[inline]
    #[must_use]
    pub const fn granularity(&self) -> Iirg {
        match extract_bits(self.0, 61, 60) {
            1 => Iirg::Global,
            2 => Iirg::Domain,
            3 => Iirg::Page,
            _ => Iirg::Reserved,
        }
    }

    /// Domain id.
    #[inline]
    #[must_use]
    pub const fn did(&self) -> u16 {
        extract_bits(self.0, 47, 32) as u16
    }
}

/// Invalidation Address register word (`IVA_REG`, at `ECAP.IRO`).
///
/// * bits 63:12 — address
/// * bits 5:0 — address mask (AM)
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Iva(pub u64);

impl Iva {
    /// Build an IVA word for `addr` (page aligned) with address mask `am`.
    #[inline]
    #[must_use]
    pub const fn new(addr: u64, am: u8) -> Self {
        Self((addr & !0xfff) | ((am & 0x3f) as u64))
    }

    /// Address.
    #[inline]
    #[must_use]
    pub const fn addr(&self) -> u64 {
        extract_bits(self.0, 63, 12) << 12
    }

    /// Address mask.
    #[inline]
    #[must_use]
    pub const fn am(&self) -> u8 {
        extract_bits(self.0, 5, 0) as u8
    }
}

// ---------------------------------------------------------------------------
// Fault status register (spec 11.4.7.1)
// ---------------------------------------------------------------------------

bitflags! {
    /// Fault Status Register (`FSTS`) bits.
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct Fsts: u32 {
        /// Primary fault overflow (PFO).
        const PFO = 1 << 0;
        /// Primary pending fault (PPF).
        const PPF = 1 << 1;
        /// Fault record index (FRI) — bits 12:8, not expressed here.
        const _ = 0;
        /// Invalidation queue error (IQE).
        const IQE = 1 << 2;
        /// Interrupt remapping table error (ITE).
        const ITE = 1 << 3;
        /// Prohibited page fault (PPF high bit? reserved alias).
        const PRO = 1 << 4;
    }
}

/// Extract the Fault Record Index (FRI) from an `FSTS` value (bits 12:8).
#[inline]
#[must_use]
pub const fn fsts_fri(fsts: u32) -> u8 {
    extract_bits(fsts as u64, 12, 8) as u8
}

// ---------------------------------------------------------------------------
// tock-registers view of the fixed register block
// ---------------------------------------------------------------------------

register_bitfields! [u32,
    /// Fault Event Control Register fields.
    pub Fectl [
        /// Interrupt enable.
        INTR_EN OFFSET(0) NUMBITS(1) [],
        /// Mask any in-flight interrupt.
        INTR_MASK OFFSET(1) NUMBITS(1) [],
        /// Pending status (read-only).
        INTR_PENDING OFFSET(31) NUMBITS(1) []
    ]
];

register_bitfields! [u32,
    /// Global Command / Status register fields (tock-registers view).
    ///
    /// Named `GcmdF` to avoid clashing with the [`Gcmd`] bitflags type used
    /// for building command words. Bits are shared by GCMD (write side) and
    /// GSTS (read side), which mirror each other bit for bit.
    pub GcmdF [
        /// Translation enable / enabled.
        TE OFFSET(31) NUMBITS(1) [],
        /// Set root table pointer / root table set.
        SRTP OFFSET(30) NUMBITS(1) [],
        /// Set fault log / fault log set.
        SFL OFFSET(29) NUMBITS(1) [],
        /// Write buffer flush / flushed.
        WBF OFFSET(28) NUMBITS(1) [],
        /// ATS enable / enabled.
        EA OFFSET(27) NUMBITS(1) [],
        /// Queued invalidation enable / enabled.
        QIE OFFSET(26) NUMBITS(1) [],
        /// Interrupt remapping enable / enabled.
        IRE OFFSET(25) NUMBITS(1) [],
        /// Set interrupt remap table pointer / set.
        SIRTP OFFSET(24) NUMBITS(1) [],
        /// Compatibility format interrupt / pending.
        CFI OFFSET(23) NUMBITS(1) []
    ]
];

register_structs! {
    /// Fixed part of the VT-d MMIO register block (offsets 000h..0C0h).
    ///
    /// Capability-relative registers (IOTLB, fault records, performance
    /// monitoring, virtual commands) are *not* part of this block because
    /// their offsets depend on `CAP`/`ECAP`.
    pub DmarRegs {
        (0x000 => version: ReadWrite<u32>),
        (0x004 => _r0),
        (0x008 => cap_lo: ReadWrite<u32>),
        (0x00c => cap_hi: ReadWrite<u32>),
        (0x010 => ecap_lo: ReadWrite<u32>),
        (0x014 => ecap_hi: ReadWrite<u32>),
        (0x018 => gcmd: ReadWrite<u32, GcmdF::Register>),
        (0x01c => gsts: ReadWrite<u32>),
        (0x020 => rtaddr: ReadWrite<u64>),
        (0x028 => ccmd: ReadWrite<u64>),
        (0x030 => _r1),
        (0x034 => fsts: ReadWrite<u32>),
        (0x038 => fectl: ReadWrite<u32, Fectl::Register>),
        (0x03c => fedata: ReadWrite<u32>),
        (0x040 => feaddr: ReadWrite<u32>),
        (0x044 => feuaddr: ReadWrite<u32>),
        (0x048 => _r2),
        (0x064 => pmen: ReadWrite<u32>),
        (0x068 => plmbase: ReadWrite<u32>),
        (0x06c => plmlimit: ReadWrite<u32>),
        (0x070 => phmbase: ReadWrite<u64>),
        (0x078 => phmlimit: ReadWrite<u64>),
        (0x080 => iqh: ReadWrite<u64>),
        (0x088 => iqt: ReadWrite<u64>),
        (0x090 => iqa: ReadWrite<u64>),
        (0x098 => _r3),
        (0x09c => ics: ReadWrite<u32>),
        (0x0a0 => iectl: ReadWrite<u32>),
        (0x0a4 => iedata: ReadWrite<u32>),
        (0x0a8 => ieaddr: ReadWrite<u32>),
        (0x0ac => ieuaddr: ReadWrite<u32>),
        (0x0b0 => iqercd: ReadWrite<u64>),
        (0x0b8 => irta: ReadWrite<u64>),
        (0x0c0 => @END),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_fields_decode() {
        // ND=110b (16-bit domains), RWBF, CM, SAGAW=0b1100 (39+48 bit),
        // MGAW=47, FRO=1, SLLPS=0011 (2M+1G), PSI, NFR=2, MAMV=9.
        let mut raw = 0u64;
        raw |= 0b110;
        raw |= 1 << 4;
        raw |= 1 << 7;
        raw |= 0b1100 << 8;
        raw |= 47 << 16;
        raw |= 1 << 24; // FRO
        raw |= 0b0011 << 34;
        raw |= 1 << 39;
        raw |= 1 << 40; // NFR = 2
        raw |= 9 << 48;
        raw |= 1 << 56; // FS1GP
        raw |= 1 << 59; // PI
        raw |= 1 << 60; // FS5LP

        let cap = Cap::new(raw);
        assert_eq!(cap.domain_ids(), 1 << (4 + 2 * 6));
        assert!(cap.rwbf());
        assert!(cap.caching_mode());
        assert_eq!(cap.sagaw(), 0b1100);
        assert_eq!(cap.mgaw(), 48);
        assert_eq!(cap.fault_rec_offset_raw(), 1);
        assert_eq!(cap.sslps(), 0b0011);
        assert!(cap.page_selective_inval());
        assert_eq!(cap.num_fault_regs(), 2);
        assert_eq!(cap.max_amask_value(), 9);
        assert!(cap.fs_1g_pages());
        assert!(cap.posted_interrupts());
        assert!(cap.fs_5level());
        assert_eq!(fault_rec_offset(cap, 0), 16);
        assert_eq!(fault_rec_offset(cap, 1), 32);
    }

    #[test]
    fn ecap_fields_decode() {
        let mut raw = 0u64;
        raw |= 1; // C
        raw |= 0b1111 << 1; // QI, DT, IR, EIM
        raw |= 1 << 6; // PT
        raw |= 1 << 7; // SC
        raw |= 3 << 8; // IRO = 3 -> offset 48
        raw |= 0xf << 20; // MHMV
        raw |= 1 << 26; // NEST
        raw |= 0b1001 << 35; // PSS bits
        raw |= 1 << 43; // SMTS
        raw |= 1 << 55; // HPTS
        raw |= 1 << 61; // EIMER
        raw |= 1 << 62; // IRREQ

        let ecap = Ecap::new(raw);
        assert!(ecap.coherent());
        assert!(ecap.queued_inval());
        assert!(ecap.dev_tlb());
        assert!(ecap.intr_remap());
        assert!(ecap.extended_intr_mode());
        assert!(ecap.pass_through());
        assert!(ecap.snoop_control());
        assert_eq!(ecap.iotlb_offset_raw(), 3);
        assert_eq!(ecap.max_handle_mask(), 0xf);
        assert!(ecap.nested());
        assert!(ecap.scalable_mode());
        assert!(ecap.host_permission_table());
        assert!(ecap.eim_required());
        assert!(ecap.ir_required());
        let (iva, iotlb) = iotlb_offset(ecap);
        assert_eq!(iva, 48);
        assert_eq!(iotlb, 56);
    }

    #[test]
    fn gcmd_gsts_roundtrip() {
        // ENABLE (31) | SRTP (30) | QIE (26).
        let cmd = Gcmd::ENABLE | Gcmd::SRTP | Gcmd::QIE;
        assert_eq!(cmd.bits(), 0xC400_0000);
        // GSTS mirrors GCMD bit positions on the read side.
        assert!(Gsts::from_bits_truncate(0xE400_0000).contains(Gsts::TES | Gsts::RTPS));
    }

    #[test]
    fn ccmd_encoding() {
        // Use a SID with zero low bits so the FM position (bits 33:32,
        // overlapping the SID field) reads back as 0.
        let c = Ccmd::new(Cirg::Device, 0x1234, 0xabcc, 0);
        assert_eq!(c.granularity(), Cirg::Device);
        assert_eq!(c.did(), 0x1234);
        assert_eq!(c.sid(), 0xabcc);
        assert_eq!(c.fm(), 0);
        // FM lives at bits 33:32 — the low two bits of the SID field.
        let masked = Ccmd::new(Cirg::Device, 0x1234, 0xfffc, 3);
        assert_eq!(masked.fm(), 3);
        assert_eq!(masked.sid(), 0xffff);
        let c2 = Ccmd(c.0 | 1 << 63);
        assert!(c2.initiate());
    }

    #[test]
    fn iqa_irta_iva() {
        let iqa = Iqa::new(0x1234_5000, true);
        assert_eq!(iqa.base(), 0x1234_5000);
        assert!(iqa.wide_descriptors());

        // IRTA: S lives at bits 15:14 and EIME at bit 11, inside the page
        // offset — the table base must be aligned to its own size. Use a
        // 64 KiB-aligned base so the fields do not collide with address
        // bits for the size assertion, then check each field.
        let irta = Irta::new(0xdead_0000, 3, true);
        assert_eq!(irta.size_order(), 3);
        assert!(irta.eime());
        let irta0 = Irta::new(0xdead_0000, 0, false);
        assert_eq!(irta0.base(), 0xdead_0000);
        assert_eq!(irta0.size_order(), 0);
        assert!(!irta0.eime());

        let iva = Iva::new(0x12_3456_7000, 9);
        assert_eq!(iva.addr(), 0x12_3456_7000);
        assert_eq!(iva.am(), 9);
    }

    #[test]
    fn iotlb_inval_word() {
        let w = IotlbInval::new(Iirg::Page, 0x42, true, false);
        assert_eq!(w.granularity(), Iirg::Page);
        assert_eq!(w.did(), 0x42);
        let initiate = IotlbInval(w.0 | 1 << 63);
        assert!(initiate.initiate());
    }

    #[test]
    fn version_and_fri() {
        assert_eq!(Version::new(0x65).major, 6);
        assert_eq!(Version::new(0x65).minor, 5);
        assert_eq!(fsts_fri(0x1f00), 0x1f);
    }
}
