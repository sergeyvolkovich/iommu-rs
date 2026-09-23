//! ACPI DMA Remapping (DMAR) table parsing.
//!
//! Implements the table header (section 8.1) and every remapping structure
//! type defined in section 8.2 of the VT-d specification:
//!
//! | Type | Structure                                          | Section |
//! |------|----------------------------------------------------|---------|
//! | 0    | [`Drhd`] — Hardware Unit Definition                | 8.3     |
//! | 1    | [`Rmrr`] — Reserved Memory Region Reporting        | 8.4     |
//! | 2    | [`Atsr`] — Root Port ATS Capability Reporting      | 8.5     |
//! | 3    | [`Rhsa`] — Remapping Hardware Static Affinity      | 8.6     |
//! | 4    | [`Andd`] — ACPI Name-space Device Declaration      | 8.7     |
//! | 5    | [`Satc`] — SoC Integrated ATC Reporting            | 8.8     |
//! | 6    | [`Sidp`] — SoC Integrated Device Property          | 8.9     |
//!
//! The parser never allocates: it walks the raw table bytes and yields
//! borrowed views ([`RemapStruct::Drhd(&Drhd)`] etc.), so it can run from a
//! bootloader, kernel or firmware environment.
//!
//! ```
//! use intel_iommu::dmar::{DmarTable, RemapStruct};
//!
//! static DMAR: &[u8] = &[
//!     b'D', b'M', b'A', b'R', 64, 0, 0, 0, // sig + length (u32) = 64
//!     1, 0xBD,                             // revision, checksum
//!     b'O', b'E', b'M', b' ', b' ', b' ',   // OEM id
//!     b'T', b'B', b'L', b' ', b' ', b' ', b' ', b' ', // OEM table id
//!     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // OEM rev, creator id/rev
//!     52 - 1, 0,                            // HAW (52-bit), flags
//!     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,         // reserved[10]
//!     // DRHD: type=0, length=16, flags=0, size=1, segment=0, base=0xfed90000
//!     0, 0, 16, 0, 0, 1, 0, 0, 0x00, 0x00, 0xd9, 0xfe, 0, 0, 0, 0,
//! ];
//!
//! let dmar = DmarTable::new(DMAR).unwrap();
//! assert_eq!(dmar.host_address_width(), 52);
//! for s in dmar.structs() {
//!     if let RemapStruct::Drhd(drhd) = s {
//!         assert_eq!(drhd.register_base(), 0xfed90000);
//!         assert_eq!(drhd.segment(), 0);
//!     }
//! }
//! ```

use core::fmt;

/// Error returned while interpreting a DMAR table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarError {
    /// Table shorter than the smallest valid DMAR (48 bytes).
    TooShort {
        /// Actual byte length.
        len: usize,
    },
    /// Signature is not `DMAR`.
    BadSignature([u8; 4]),
    /// Header length field is inconsistent with the buffer, or a structure
    /// overruns the table.
    BadLength {
        /// Length claimed by the header or structure.
        claimed: usize,
        /// Bytes actually available.
        available: usize,
    },
    /// ACPI checksum (byte sum modulo 256) is not zero.
    BadChecksum,
}

impl fmt::Display for DmarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DmarError::TooShort { len } => write!(f, "DMAR table too short: {len} bytes"),
            DmarError::BadSignature(sig) => write!(f, "bad DMAR signature: {sig:02x?}"),
            DmarError::BadLength { claimed, available } => {
                write!(f, "bad length: claimed {claimed}, available {available}")
            }
            DmarError::BadChecksum => write!(f, "checksum mismatch"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DmarError {}

/// Offset of the first remapping structure (36-byte header + HAW + flags +
/// reserved[10]).
const STRUCTS_OFFSET: usize = 48;

/// A parsed view of the ACPI DMAR table.
#[derive(Debug, Clone, Copy)]
pub struct DmarTable<'a> {
    raw: &'a [u8],
}

impl<'a> DmarTable<'a> {
    /// Validate `raw` as a DMAR table and return a borrowed view.
    ///
    /// Checks signature, minimum length, header length consistency and the
    /// ACPI checksum (byte sum must be `0 mod 256`).
    pub fn new(raw: &'a [u8]) -> Result<Self, DmarError> {
        if raw.len() < STRUCTS_OFFSET {
            return Err(DmarError::TooShort { len: raw.len() });
        }
        if raw[..4] != *b"DMAR" {
            return Err(DmarError::BadSignature(raw[..4].try_into().unwrap()));
        }
        let total = u32::from_le_bytes(raw[4..8].try_into().expect("4 bytes")) as usize;
        if total < STRUCTS_OFFSET || total > raw.len() {
            return Err(DmarError::BadLength {
                claimed: total,
                available: raw.len(),
            });
        }
        if raw[..total].iter().fold(0u8, |a, b| a.wrapping_add(*b)) != 0 {
            return Err(DmarError::BadChecksum);
        }
        Ok(DmarTable { raw: &raw[..total] })
    }

    /// Signature bytes (`DMAR`).
    #[must_use]
    pub fn signature(&self) -> [u8; 4] {
        self.raw[..4].try_into().expect("checked in new")
    }

    /// Table revision (usually 1).
    #[must_use]
    pub fn revision(&self) -> u8 {
        self.raw[8]
    }

    /// OEM id as bytes (6 characters, space padded).
    #[must_use]
    pub fn oem_id(&self) -> [u8; 6] {
        self.raw[10..16].try_into().expect("header is 36 bytes")
    }

    /// Host Address Width: the platform HAW is `value + 1` bits.
    #[must_use]
    pub fn host_address_width(&self) -> u8 {
        self.raw[36] + 1
    }

    /// Raw DMAR flags byte (bit 0: INTR_REMAP, bit 1: X2APIC_OPT_OUT,
    /// bit 3: DMA_REMAP_OPT_OUT).
    #[must_use]
    pub fn flags_raw(&self) -> u8 {
        self.raw[37]
    }

    /// Interrupt remapping required (flags bit 0).
    #[must_use]
    pub fn intr_remap_required(&self) -> bool {
        self.flags_raw() & 0b1 != 0
    }

    /// x2APIC opt-out requested (flags bit 1).
    #[must_use]
    pub fn x2apic_opt_out(&self) -> bool {
        self.flags_raw() & 0b10 != 0
    }

    /// Iterate over the remapping structures in declaration order.
    ///
    /// Structures with unknown types are surfaced as
    /// [`RemapStruct::Unknown`] so forward compatibility is lossless.
    #[must_use]
    pub fn structs(&self) -> StructIter<'a> {
        StructIter {
            bytes: &self.raw[STRUCTS_OFFSET..],
        }
    }

    /// All DRHD units, in table order.
    pub fn drhd_units(&self) -> impl Iterator<Item = Drhd<'a>> {
        self.structs().filter_map(|s| match s {
            RemapStruct::Drhd(d) => Some(d),
            _ => None,
        })
    }
}

/// One remapping structure, borrowed from the table.
#[derive(Debug)]
pub enum RemapStruct<'a> {
    /// DMA Remapping Hardware Unit Definition (type 0).
    Drhd(Drhd<'a>),
    /// Reserved Memory Region Reporting (type 1).
    Rmrr(Rmrr<'a>),
    /// Root Port ATS Capability Reporting (type 2).
    Atsr(Atsr<'a>),
    /// Remapping Hardware Static Affinity (type 3).
    Rhsa(Rhsa<'a>),
    /// ACPI Name-space Device Declaration (type 4).
    Andd(Andd<'a>),
    /// SoC Integrated Address Translation Cache (type 5).
    Satc(Satc<'a>),
    /// SoC Integrated Device Property (type 6).
    Sidp(Sidp<'a>),
    /// A structure type this crate does not model (`ty > 6`).
    Unknown {
        /// Structure type code.
        ty: u8,
        /// Full raw bytes of the structure (header included).
        raw: &'a [u8],
    },
}

/// Iterator over remapping structures.
///
/// Iteration stops when the table is exhausted. A structure whose length
/// overruns the remaining bytes terminates the iteration: structure
/// boundaries are length-defined and cannot be re-synchronised.
#[derive(Debug, Clone)]
pub struct StructIter<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for StructIter<'a> {
    type Item = RemapStruct<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (ty, len) = (self.bytes.first()?, peek_len(self.bytes)?);
        if len < 4 || len > self.bytes.len() {
            return None;
        }
        let (raw, rest) = self.bytes.split_at(len);
        self.bytes = rest;
        Some(match ty {
            0 => RemapStruct::Drhd(Drhd { raw }),
            1 => RemapStruct::Rmrr(Rmrr { raw }),
            2 => RemapStruct::Atsr(Atsr { raw }),
            3 => RemapStruct::Rhsa(Rhsa { raw }),
            4 => RemapStruct::Andd(Andd { raw }),
            5 => RemapStruct::Satc(Satc { raw }),
            6 => RemapStruct::Sidp(Sidp { raw }),
            _ => RemapStruct::Unknown { ty: *ty, raw },
        })
    }
}

/// Read the 16-bit length field (bytes 2..4) if present.
fn peek_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 4 {
        None
    } else {
        Some(u16::from_le_bytes([bytes[2], bytes[3]]) as usize)
    }
}

/// Read a little-endian u16 at `off`, or 0 when out of range.
fn le16(raw: &[u8], off: usize) -> u16 {
    match raw.get(off..off + 2) {
        Some(b) => u16::from_le_bytes([b[0], b[1]]),
        None => 0,
    }
}

/// Read a little-endian u64 at `off`, or 0 when out of range.
fn le64(raw: &[u8], off: usize) -> u64 {
    match raw.get(off..off + 8) {
        Some(b) => u64::from_le_bytes(b.try_into().expect("8 bytes")),
        None => 0,
    }
}

macro_rules! scope_struct {
    ($(#[$meta:meta])* $name:ident, $fixed:expr, { $($(#[$fmeta:meta])* $acc:ident : $ty:ty = $expr:expr;)* }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy)]
        pub struct $name<'a> {
            raw: &'a [u8],
        }

        impl<'a> $name<'a> {
            /// Full raw bytes of the structure (header included).
            #[must_use]
            pub fn raw(&self) -> &'a [u8] {
                self.raw
            }

            /// Device scope entries trailing the fixed part.
            pub fn scopes(&self) -> DeviceScopeIter<'a> {
                DeviceScopeIter {
                    bytes: self.raw.get($fixed..).unwrap_or(&[]),
                }
            }

            $($(#[$fmeta])*
            #[must_use]
            pub fn $acc(&self) -> $ty { $expr(self.raw) })*
        }
    };
}

scope_struct! {
    /// DMA Remapping Hardware Unit Definition (type 0, section 8.3).
    Drhd, 16, {
        /// `INCLUDE_PCI_ALL` flag (bit 0 of flags).
        include_pci_all: bool = |r: &[u8]| r.get(4).copied().unwrap_or(0) & 1 != 0;
        /// Register-set size order `N`: MMIO area occupies `2^(N+12)` bytes.
        register_size_order: u8 = |r: &[u8]| r.get(5).copied().unwrap_or(0) & 0x0f;
        /// PCI segment number.
        segment: u16 = |r: &[u8]| le16(r, 6);
        /// Base physical address of the remapping hardware register set.
        register_base: u64 = |r: &[u8]| le64(r, 8);
    }
}

impl Drhd<'_> {
    /// Size of the register set in bytes (`2^(N+12)`).
    #[must_use]
    pub fn register_size(&self) -> u64 {
        1u64 << (12 + u32::from(self.register_size_order()))
    }
}

scope_struct! {
    /// Reserved Memory Region Reporting structure (type 1, section 8.4).
    Rmrr, 24, {
        /// PCI segment number.
        segment: u16 = |r: &[u8]| le16(r, 6);
        /// Inclusive base physical address of the reserved region.
        base: u64 = |r: &[u8]| le64(r, 8);
        /// Inclusive limit (last byte) physical address of the region.
        limit: u64 = |r: &[u8]| le64(r, 16);
    }
}

scope_struct! {
    /// Root Port ATS Capability Reporting structure (type 2, section 8.5).
    Atsr, 8, {
        /// `ALL_PORTS` flag (bit 0): all ports below a single root port.
        all_ports: bool = |r: &[u8]| r.get(4).copied().unwrap_or(0) & 1 != 0;
        /// PCI segment number.
        segment: u16 = |r: &[u8]| le16(r, 6);
    }
}

scope_struct! {
    /// SoC Integrated Address Translation Cache structure (type 5, section 8.8).
    Satc, 8, {
        /// `ATC_REQUIRED` flag (bit 0).
        atc_required: bool = |r: &[u8]| r.get(4).copied().unwrap_or(0) & 1 != 0;
        /// PCI segment number.
        segment: u16 = |r: &[u8]| le16(r, 6);
    }
}

scope_struct! {
    /// SoC Integrated Device Property structure (type 6, section 8.9).
    Sidp, 8, {
        /// PCI segment number.
        segment: u16 = |r: &[u8]| le16(r, 6);
    }
}

/// Remapping Hardware Static Affinity structure (type 3, section 8.6).
///
/// Fixed 20-byte structure: header (4) + reserved (4) + segment (4) +
/// base address (8) + proximity domain (4).
#[derive(Debug, Clone, Copy)]
pub struct Rhsa<'a> {
    raw: &'a [u8],
}

impl Rhsa<'_> {
    /// PCI segment number.
    #[must_use]
    pub fn segment(&self) -> u32 {
        le32(self.raw, 8)
    }

    /// Base physical address of the remapping unit.
    #[must_use]
    pub fn base(&self) -> u64 {
        le64(self.raw, 12)
    }

    /// Proximity domain this unit is closest to.
    #[must_use]
    pub fn proximity_domain(&self) -> u32 {
        le32(self.raw, 20)
    }
}

/// ACPI Name-space Device Declaration structure (type 4, section 8.7).
///
/// Layout: header (4) + reserved[3] (4..7) + ACPI device number (1) +
/// PCI segment (2) + ACPI object name (variable, NUL-terminated).
#[derive(Debug, Clone, Copy)]
pub struct Andd<'a> {
    raw: &'a [u8],
}

impl Andd<'_> {
    /// ACPI device number shared with a device-scope entry (type `05h`)
    /// referencing this declaration.
    #[must_use]
    pub fn acpi_device_number(&self) -> u8 {
        self.raw.get(7).copied().unwrap_or(0)
    }

    /// PCI segment number.
    #[must_use]
    pub fn segment(&self) -> u16 {
        le16(self.raw, 8)
    }

    /// ACPI namespace object name (without the trailing NUL).
    #[must_use]
    pub fn object_name(&self) -> &[u8] {
        let body = self.raw.get(10..).unwrap_or(&[]);
        let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
        &body[..end]
    }
}

/// Read a little-endian u32 at `off`, or 0 when out of range.
fn le32(raw: &[u8], off: usize) -> u32 {
    match raw.get(off..off + 4) {
        Some(b) => u32::from_le_bytes(b.try_into().expect("4 bytes")),
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Device scope entries (section 8.3.1)
// ---------------------------------------------------------------------------

/// Device scope entry types (section 8.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScopeType {
    /// `0x01` — PCI endpoint device.
    PciEndpoint,
    /// `0x02` — PCI sub-hierarchy (bridge + all downstream devices).
    PciSubhierarchy,
    /// `0x03` — I/O APIC (I/O SAPIC).
    Ioapic,
    /// `0x04` — MSI-capable HPET timer block.
    MsiCapableHpet,
    /// `0x05` — ACPI name-space enumerated device.
    AcpiNamespaceDevice,
    /// Any other value (reserved for future use).
    Reserved(u8),
}

impl From<u8> for ScopeType {
    fn from(v: u8) -> Self {
        match v {
            0x01 => ScopeType::PciEndpoint,
            0x02 => ScopeType::PciSubhierarchy,
            0x03 => ScopeType::Ioapic,
            0x04 => ScopeType::MsiCapableHpet,
            0x05 => ScopeType::AcpiNamespaceDevice,
            other => ScopeType::Reserved(other),
        }
    }
}

/// One device scope entry (section 8.3.1).
///
/// Byte layout: type (1) + length (1) + flags (2) + enumeration id (1) +
/// start bus (1) + path (variable, `{device, function}` byte pairs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceScope<'a> {
    /// Entry type.
    pub ty: ScopeType,
    /// PCI bus number the path starts from.
    pub bus: u8,
    /// Enumeration id (for HPET / ACPI-namespace devices).
    pub enumeration_id: u8,
    /// Raw scope flags (meaningful inside SIDP structures).
    pub flags: u16,
    /// PCI path as `{device, function}` byte pairs from `bus`.
    pub path: &'a [u8],
}

impl DeviceScope<'_> {
    /// First-level PCI source identifier `(bus << 8) | (dev << 3) | fn`.
    ///
    /// This is the source-id for endpoint entries whose path holds exactly
    /// one `{device, function}` pair. Entries with a deeper path (bridge
    /// sub-hierarchies) require PCI configuration-space walking to resolve
    /// the final secondary bus — the caller performs that walk and advances
    /// through [`Self::path`] pair by pair.
    #[must_use]
    pub fn first_source_id(&self) -> Option<u16> {
        let mut pairs = self.path.chunks_exact(2);
        let pair = pairs.next()?;
        Some(
            (u16::from(self.bus) << 8)
                | (u16::from(pair[0]) << 3)
                | u16::from(pair[1] & 0x07),
        )
    }

    /// Iterate the `{device, function}` pairs of the path.
    pub fn path_pairs(&self) -> impl Iterator<Item = (u8, u8)> + '_ {
        self.path.chunks_exact(2).map(|p| (p[0], p[1]))
    }
}

/// Iterator over device scope entries in a scope list.
#[derive(Debug, Clone)]
pub struct DeviceScopeIter<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for DeviceScopeIter<'a> {
    type Item = DeviceScope<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.len() < 6 {
            return None;
        }
        let ty = self.bytes[0];
        let len = self.bytes[1] as usize;
        if len < 6 || len > self.bytes.len() {
            return None;
        }
        let (raw, rest) = self.bytes.split_at(len);
        self.bytes = rest;
        Some(DeviceScope {
            ty: ScopeType::from(ty),
            enumeration_id: raw[4],
            bus: raw[5],
            flags: u16::from_le_bytes([raw[2], raw[3]]),
            path: &raw[6..],
        })
    }
}
