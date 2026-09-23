//! ACPI IVRS (I/O Virtualization Reporting Structure) — appendix A.
//!
//! The IVRS table contains:
//!
//! * one or more **IVHD** (I/O Virtualization Hardware Definition) blocks
//!   describing each IOMMU: type `10h` (legacy), `11h` (v2 features) and
//!   `40h` (v3 / "miscellaneous range" register support);
//! * zero or more **IVMD** (I/O Virtualization Memory Definition) blocks
//!   (types `20h`/`22h`/`21h`? — `20h` reserved, `21h`/`22h` define
//!   reserved-memory ranges).
//!
//! Device entries inside an IVHD are 4-byte (ALL/SELECT), 8-byte
//! (ALIAS/LAPIC) or variable-length (`40h`/`41h`/`42h` special devices).
//!
//! ```
//! use amd_iommu::ivrs::{IvrsTable, Ivhd, EntryType};
//!
//! // Minimal IVRS with a type-10h IVHD header, no device entries.
//! static IVRS: &[u8] = &[
//!     b'I', b'V', b'R', b'S', 65, 0, 0, 0, 1, 0x72, // sig, len(u32), rev, cksum
//!     b'A', b'M', b'D', b' ', b' ', b' ',           // OEM id
//!     b'I', b'V', b'R', b'S', b' ', b' ', b' ', b' ', // OEM table id
//!     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,           // OEM rev, creator id/rev
//!     0, 0, 0, 0, 0, 0, 0, 0,                       // IVInfo + reserved
//!     // IVHD type 10h: type, flags, length(u16) = 21, iommu id
//!     0x10, 0, 21, 0, 0,
//!     // PCI segment (2), base address (8) = 0xfed8_0000
//!     0, 0, 0x00, 0x00, 0xd8, 0xfe, 0, 0, 0, 0,
//!     // device range (2)
//!     0, 0,
//!     // capability dword (4)
//!     0xff, 0x18, 0, 0,
//! ];
//!
//! let ivrs = IvrsTable::new(IVRS).unwrap();
//! let hd = ivrs.ivhd_units().next().unwrap();
//! assert_eq!(hd.entry_type(), EntryType::IvhdType10);
//! assert_eq!(hd.base_address(), 0xfed8_0000);
//! ```

use core::fmt;

/// Error returned while interpreting an IVRS table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IvrsError {
    /// Table shorter than 48 bytes.
    TooShort {
        /// Actual length.
        len: usize,
    },
    /// Signature is not `IVRS`.
    BadSignature([u8; 4]),
    /// Header length inconsistent with buffer, or a block overruns it.
    BadLength {
        /// Claimed length.
        claimed: usize,
        /// Available bytes.
        available: usize,
    },
    /// ACPI checksum mismatch.
    BadChecksum,
}

impl fmt::Display for IvrsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IvrsError::TooShort { len } => write!(f, "IVRS table too short: {len} bytes"),
            IvrsError::BadSignature(sig) => write!(f, "bad IVRS signature: {sig:02x?}"),
            IvrsError::BadLength { claimed, available } => {
                write!(f, "bad length: claimed {claimed}, available {available}")
            }
            IvrsError::BadChecksum => write!(f, "checksum mismatch"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IvrsError {}

/// Offset of the first block (36-byte header + virtualization info[8]).
const BLOCKS_OFFSET: usize = 44;

/// A parsed view of the ACPI IVRS table.
#[derive(Debug, Clone, Copy)]
pub struct IvrsTable<'a> {
    raw: &'a [u8],
}

impl<'a> IvrsTable<'a> {
    /// Validate `raw` as an IVRS table.
    pub fn new(raw: &'a [u8]) -> Result<Self, IvrsError> {
        if raw.len() < BLOCKS_OFFSET {
            return Err(IvrsError::TooShort { len: raw.len() });
        }
        if raw[..4] != *b"IVRS" {
            return Err(IvrsError::BadSignature(raw[..4].try_into().unwrap()));
        }
        let total = u32::from_le_bytes(raw[4..8].try_into().expect("4 bytes")) as usize;
        if total < BLOCKS_OFFSET || total > raw.len() {
            return Err(IvrsError::BadLength {
                claimed: total,
                available: raw.len(),
            });
        }
        if raw[..total].iter().fold(0u8, |a, b| a.wrapping_add(*b)) != 0 {
            return Err(IvrsError::BadChecksum);
        }
        Ok(IvrsTable { raw: &raw[..total] })
    }

    /// Table revision.
    #[must_use]
    pub fn revision(&self) -> u8 {
        self.raw[8]
    }

    /// ACPI checksum byte.
    #[must_use]
    pub fn checksum(&self) -> u8 {
        self.raw[9]
    }

    /// Iterate over all IVHD / IVMD blocks in declaration order.
    #[must_use]
    pub fn blocks(&self) -> BlockIter<'a> {
        BlockIter {
            bytes: &self.raw[BLOCKS_OFFSET..],
        }
    }

    /// All IVHD (hardware definition) blocks.
    pub fn ivhd_units(&self) -> impl Iterator<Item = Ivhd<'a>> {
        self.blocks().filter_map(|b| match b {
            Block::Ivhd(h) => Some(h),
            _ => None,
        })
    }

    /// All IVMD (memory definition) blocks.
    pub fn ivmd_units(&self) -> impl Iterator<Item = Ivmd<'a>> {
        self.blocks().filter_map(|b| match b {
            Block::Ivmd(m) => Some(m),
            _ => None,
        })
    }
}

/// Block type codes (appendix A.2 / A.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EntryType {
    /// `10h` — IVHD, legacy device entry formats.
    IvhdType10,
    /// `11h` — IVHD with expanded feature reporting.
    IvhdType11,
    /// `40h` — IVHD v3 (miscellaneous range registers, guest-vAPIC).
    IvhdType40,
    /// `20h` — IVMD.
    Ivmd,
    /// Any other / reserved type.
    Reserved(u8),
}

impl From<u8> for EntryType {
    fn from(v: u8) -> Self {
        match v {
            0x10 => EntryType::IvhdType10,
            0x11 => EntryType::IvhdType11,
            0x20 => EntryType::Ivmd,
            0x40 => EntryType::IvhdType40,
            other => EntryType::Reserved(other),
        }
    }
}

/// One IVRS block, borrowed from the table.
#[derive(Debug)]
pub enum Block<'a> {
    /// I/O virtualization hardware definition.
    Ivhd(Ivhd<'a>),
    /// I/O virtualization memory definition.
    Ivmd(Ivmd<'a>),
    /// Unknown block type.
    Unknown {
        /// Block type.
        ty: u8,
        /// Raw bytes.
        raw: &'a [u8],
    },
}

/// Iterator over IVRS blocks; stops on a length-inconsistent tail.
#[derive(Debug, Clone)]
pub struct BlockIter<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for BlockIter<'a> {
    type Item = Block<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.len() < 4 {
            return None;
        }
        let ty = self.bytes[0];
        let len = u16::from_le_bytes([self.bytes[2], self.bytes[3]]) as usize;
        if len < 4 || len > self.bytes.len() {
            return None;
        }
        let (raw, rest) = self.bytes.split_at(len);
        self.bytes = rest;
        Some(match EntryType::from(ty) {
            EntryType::IvhdType10 | EntryType::IvhdType11 | EntryType::IvhdType40 => {
                Block::Ivhd(Ivhd { raw })
            }
            EntryType::Ivmd => Block::Ivmd(Ivmd { raw }),
            EntryType::Reserved(_) => Block::Unknown { ty, raw },
        })
    }
}

/// I/O Virtualization Hardware Definition block (IVHD).
///
/// Layout: type (1) + flags (1) + length (2) + device-entry area. Type-10h
/// entries additionally carry `type10_flags`, IOMMU identifier, PCI
/// segment, base address, range and capability words; types 11h/40h add
/// feature and register info dwords.
#[derive(Debug, Clone, Copy)]
pub struct Ivhd<'a> {
    raw: &'a [u8],
}

impl<'a> Ivhd<'a> {
    /// Block type.
    #[must_use]
    pub fn entry_type(&self) -> EntryType {
        EntryType::from(self.raw[0])
    }

    /// Block flags (bit 0: HtTunEn, bit 1: PassPW, bit 2: ResPassPW,
    /// bit 3: Coherent, bit 4: IotlbSup, bit 5: HtTunHpr? etc. — raw).
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.raw[1]
    }

    /// IOMMU identifier / PCI segment group.
    #[must_use]
    pub fn iommu_id(&self) -> u8 {
        self.raw[4]
    }

    /// PCI segment number (types 10h/11h/40h).
    #[must_use]
    pub fn segment(&self) -> u16 {
        u16::from_le_bytes([self.raw[5], self.raw[6]])
    }

    /// Base address of the IOMMU MMIO register set.
    #[must_use]
    pub fn base_address(&self) -> u64 {
        // All IVHD variants: bytes 7..15 hold the 64-bit base address.
        match self.raw.get(7..15) {
            Some(b) => u64::from_le_bytes(b.try_into().expect("8 bytes")),
            None => 0,
        }
    }

    /// PCI device range covered by this IOMMU (`first..=last` bytes).
    #[must_use]
    pub fn device_range(&self) -> Option<(u16, u16)> {
        let off = 15;
        let lo = *self.raw.get(off)? as u16;
        let hi = *self.raw.get(off + 1)? as u16;
        Some((lo, hi))
    }

    /// Raw capability word (MMIO offset 0030h mirror) for types 10h/11h.
    #[must_use]
    pub fn capability(&self) -> Option<u32> {
        let off = 17;
        let b = self.raw.get(off..off + 4)?;
        Some(u32::from_le_bytes(b.try_into().expect("4 bytes")))
    }

    /// Raw extended-feature dword for types 11h/40h (offset 0x1A0h mirror).
    #[must_use]
    pub fn extended_features(&self) -> Option<u32> {
        let off = match self.entry_type() {
            EntryType::IvhdType11 => 21,
            EntryType::IvhdType40 => 21,
            _ => return None,
        };
        let b = self.raw.get(off..off + 4)?;
        Some(u32::from_le_bytes(b.try_into().expect("4 bytes")))
    }

    /// Device entries declared in this IVHD.
    pub fn devices(&self) -> DeviceEntryIter<'a> {
        // Header size: 4 + 4 (common) + 12 (type 10h) + 4 (11h/40h extra).
        let hdr = match self.entry_type() {
            EntryType::IvhdType10 => 24,
            _ => 28,
        };
        DeviceEntryIter {
            bytes: self.raw.get(hdr..).unwrap_or(&[]),
        }
    }
}

/// I/O Virtualization Memory Definition block (IVMD).
#[derive(Debug, Clone, Copy)]
pub struct Ivmd<'a> {
    raw: &'a [u8],
}

impl<'a> Ivmd<'a> {
    /// Block flags (bit 0: exclude, bit 1: unity, bit 2: init-pass).
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.raw[1]
    }

    /// PCI segment (0 = all segments when the address width field is 32).
    #[must_use]
    pub fn segment(&self) -> u16 {
        u16::from_le_bytes([self.raw[4], self.raw[5]])
    }

    /// Base physical address of the region.
    #[must_use]
    pub fn base(&self) -> u64 {
        let b = self.raw.get(8..16).unwrap_or(&[0; 8]);
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        u64::from_le_bytes(a)
    }

    /// Length of the region in bytes.
    #[must_use]
    pub fn length(&self) -> u64 {
        let b = self.raw.get(16..24).unwrap_or(&[0; 8]);
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        u64::from_le_bytes(a)
    }
}

/// Device entry type codes (appendix A.4).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceType {
    /// `01h` — all devices on the bus.
    All,
    /// `02h` — one device (select).
    Select,
    /// `03h` — alias select (device reported under an alias id).
    AliasSelect,
    /// `40h`/`41h`/`42h` — special device (variable length).
    Special,
    /// `48h` — ACPI HID/FN (variable length).
    AcpiHid,
    /// Any other / reserved code.
    Reserved(u8),
}

impl From<u8> for DeviceType {
    fn from(v: u8) -> Self {
        match v {
            0x01 => DeviceType::All,
            0x02 => DeviceType::Select,
            0x03 => DeviceType::AliasSelect,
            0x40..=0x42 => DeviceType::Special,
            0x48 => DeviceType::AcpiHid,
            other => DeviceType::Reserved(other),
        }
    }
}

/// One device entry (parsed view).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceEntry<'a> {
    /// 4-byte entry: all/select (bus or bus+devfn).
    Short {
        /// Entry type.
        ty: DeviceType,
        /// First data byte (bus, or devfn for select).
        data: u8,
        /// Second data byte (devfn for `All`, alias devfn for others).
        data2: u8,
    },
    /// 8-byte entry: alias/LAPIC (adds a 16-bit source id).
    Long {
        /// Entry type.
        ty: DeviceType,
        /// Bus.
        bus: u8,
        /// Device-function.
        devfn: u8,
        /// Alias / target source id.
        source_id: u16,
    },
    /// Variable-length entry (special device / ACPI HID).
    Variable {
        /// Entry type.
        ty: DeviceType,
        /// Full raw bytes of the entry.
        raw: &'a [u8],
    },
}

/// Iterator over device entries in an IVHD.
#[derive(Debug, Clone)]
pub struct DeviceEntryIter<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for DeviceEntryIter<'a> {
    type Item = DeviceEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let first = *self.bytes.first()?;
        let ty = DeviceType::from(first);
        if matches!(first, 0x40 | 0x41 | 0x42 | 0x48) {
            // Variable-length: byte 1 is the total entry length.
            let len = *self.bytes.get(1)? as usize;
            if len < 4 || len > self.bytes.len() {
                return None;
            }
            let (raw, rest) = self.bytes.split_at(len);
            self.bytes = rest;
            return Some(DeviceEntry::Variable { ty, raw });
        }
        let needed = match first {
            0x01 | 0x02 => 4,
            0x03 | 0x28..=0x2f => 8,
            _ => 4,
        };
        if self.bytes.len() < needed {
            return None;
        }
        let (raw, rest) = self.bytes.split_at(needed);
        self.bytes = rest;
        Some(match needed {
            4 => DeviceEntry::Short {
                ty,
                data: raw[2],
                data2: raw[3],
            },
            _ => DeviceEntry::Long {
                ty,
                bus: raw[2],
                devfn: raw[3],
                source_id: u16::from_le_bytes([raw[6], raw[7]]),
            },
        })
    }
}
