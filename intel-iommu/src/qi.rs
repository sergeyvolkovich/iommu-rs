//! Queued invalidation (QI) descriptors.
//!
//! The invalidation queue holds fixed-size descriptors (128-bit when
//! `IQA_REG.DW = 0`, 256-bit when `IQA_REG.DW = 1`); 128-bit descriptors
//! submitted to a 256-bit queue must be padded with a zero qword. Each
//! descriptor starts with a 7-bit **type** formed by concatenating bits
//! `11:9` and `3:0` of the first qword (section 6.5.2).
//!
//! Type codes (spec table in 6.5.2, cross-checked against QEMU):
//!
//! | Code | Descriptor                        | Spec      |
//! |------|-----------------------------------|-----------|
//! | 1h   | [`QiCc`] context-cache invalidate | 6.5.2.1   |
//! | 2h   | [`QiIotlb`] IOTLB invalidate      | 6.5.2.3   |
//! | 3h   | [`QiDevTlb`] device-TLB invalidate| 6.5.2.5   |
//! | 4h   | [`QiIec`] interrupt entry cache   | 6.5.2.8   |
//! | 5h   | [`QiWait`] invalidation wait      | 6.5.2.9   |
//! | 6h   | [`QiPiotlb`] PASID-based IOTLB    | 6.5.2.4   |
//! | 7h   | [`QiPc`] PASID-cache invalidate   | 6.5.2.2   |
//! | 8h   | [`QiDevPiotlb`] PASID-based dev-TLB | 6.5.2.6 |
//! | 9h   | page group response               | 6.5.2.6.1 |
//!
//! ```
//! use intel_iommu::qi::{QiCc, QiDesc, Granularity};
//!
//! let d = QiDesc::ContextCache(
//!     QiCc::new(Granularity::Domain, 7, 0x1234, 0),
//! );
//! let raw: [u64; 2] = d.words();
//! // Type 1h in bits 11:9 | 3:0 of the first word.
//! assert_eq!(((raw[0] >> 5) & 0x70) | (raw[0] & 0xf), 1);
//! // DID = 7 at bits 31:16.
//! assert_eq!((raw[0] >> 16) & 0xffff, 7);
//! ```

use crate::bits::extract_bits;
use core::fmt;

/// Invalidation granularity (`G`) shared by context/PASID-cache/IOTLB
/// descriptors.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Granularity {
    /// Reserved encoding (00b) — treated as an invalid descriptor.
    #[default]
    Reserved,
    /// Global (01b).
    Global,
    /// Domain-selective (10b).
    Domain,
    /// Page-selective-within-domain (11b) — IOTLB only; for cache
    /// descriptors this means device-selective.
    PageOrDevice,
}

impl Granularity {
    /// Raw 2-bit encoding.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Granularity::Reserved => 0,
            Granularity::Global => 1,
            Granularity::Domain => 2,
            Granularity::PageOrDevice => 3,
        }
    }

    /// Decode from the raw 2-bit field.
    #[must_use]
    pub const fn from_bits(v: u8) -> Self {
        match v & 0x3 {
            1 => Granularity::Global,
            2 => Granularity::Domain,
            3 => Granularity::PageOrDevice,
            _ => Granularity::Reserved,
        }
    }
}

/// 7-bit descriptor type (concatenation of bits 11:9 and 3:0).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QiType(pub u8);

impl QiType {
    /// Context-cache invalidate descriptor.
    pub const CONTEXT_CACHE: QiType = QiType(0x1);
    /// IOTLB invalidate descriptor.
    pub const IOTLB: QiType = QiType(0x2);
    /// Device-TLB invalidate descriptor.
    pub const DEVICE_TLB: QiType = QiType(0x3);
    /// Interrupt entry cache invalidate descriptor.
    pub const INTERRUPT_ENTRY_CACHE: QiType = QiType(0x4);
    /// Invalidation wait descriptor.
    pub const WAIT: QiType = QiType(0x5);
    /// PASID-based IOTLB invalidate descriptor.
    pub const PASID_IOTLB: QiType = QiType(0x6);
    /// PASID-cache invalidate descriptor.
    pub const PASID_CACHE: QiType = QiType(0x7);
    /// PASID-based device-TLB invalidate descriptor.
    pub const PASID_DEVICE_TLB: QiType = QiType(0x8);
    /// Page group response descriptor.
    pub const PAGE_GROUP_RESPONSE: QiType = QiType(0x9);

    /// Extract the type from the first descriptor word.
    #[must_use]
    pub const fn from_word0(w: u64) -> Self {
        QiType(((extract_bits(w, 11, 9) << 4) | extract_bits(w, 3, 0)) as u8)
    }
}

impl fmt::Display for QiType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            QiType::CONTEXT_CACHE => write!(f, "context-cache invalidate"),
            QiType::IOTLB => write!(f, "IOTLB invalidate"),
            QiType::DEVICE_TLB => write!(f, "device-TLB invalidate"),
            QiType::INTERRUPT_ENTRY_CACHE => write!(f, "interrupt entry cache invalidate"),
            QiType::WAIT => write!(f, "invalidation wait"),
            QiType::PASID_IOTLB => write!(f, "PASID-based IOTLB invalidate"),
            QiType::PASID_CACHE => write!(f, "PASID-cache invalidate"),
            QiType::PASID_DEVICE_TLB => write!(f, "PASID-based device-TLB invalidate"),
            QiType::PAGE_GROUP_RESPONSE => write!(f, "page group response"),
            QiType(other) => write!(f, "unknown (0x{other:x})"),
        }
    }
}

/// Compose the 7-bit type field into bits 11:9 | 3:0 of word 0.
const fn type_bits(t: u8) -> u64 {
    let t = (t & 0x7f) as u64;
    ((t >> 4) << 9) | (t & 0xf)
}

/// Context-cache invalidate descriptor (128-bit, section 6.5.2.1).
///
/// Word 0: type, `G` (5:4), `DID` (31:16), `SID` (47:32), `FM` (49:48).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QiCc {
    /// Invalidation granularity.
    pub granularity: Granularity,
    /// Domain identifier.
    pub did: u16,
    /// Source identifier.
    pub sid: u16,
    /// Function mask applied to the low bits of `sid`.
    pub fm: u8,
}

impl QiCc {
    /// Build a descriptor.
    #[must_use]
    pub const fn new(granularity: Granularity, did: u16, sid: u16, fm: u8) -> Self {
        QiCc {
            granularity,
            did,
            sid,
            fm,
        }
    }

    /// Decode from descriptor words.
    #[must_use]
    pub const fn from_words(w0: u64, _w1: u64) -> Self {
        QiCc {
            granularity: Granularity::from_bits(extract_bits(w0, 5, 4) as u8),
            did: extract_bits(w0, 31, 16) as u16,
            sid: extract_bits(w0, 47, 32) as u16,
            fm: extract_bits(w0, 49, 48) as u8,
        }
    }

    /// Encode to descriptor words.
    #[must_use]
    pub const fn to_words(&self) -> [u64; 2] {
        let w0 = type_bits(QiType::CONTEXT_CACHE.0)
            | (((self.granularity.bits()) as u64) << 4)
            | (((self.did) as u64) << 16)
            | (((self.sid) as u64) << 32)
            | (((self.fm & 0x3) as u64) << 48);
        [w0, 0]
    }
}

/// IOTLB invalidate descriptor (128-bit, section 6.5.2.3).
///
/// Word 0: type, `G` (5:4), `DID` (31:16). Word 1: address (63:12),
/// address mask `AM` (5:0).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QiIotlb {
    /// Invalidation granularity.
    pub granularity: Granularity,
    /// Domain identifier.
    pub did: u16,
    /// Guest physical address to invalidate (page aligned).
    pub addr: u64,
    /// Address mask: invalidate `2^AM` pages starting at `addr`.
    pub am: u8,
}

impl QiIotlb {
    /// Build a descriptor.
    #[must_use]
    pub const fn new(granularity: Granularity, did: u16, addr: u64, am: u8) -> Self {
        QiIotlb {
            granularity,
            did,
            addr,
            am,
        }
    }

    /// Decode from descriptor words.
    #[must_use]
    pub const fn from_words(w0: u64, w1: u64) -> Self {
        QiIotlb {
            granularity: Granularity::from_bits(extract_bits(w0, 5, 4) as u8),
            did: extract_bits(w0, 31, 16) as u16,
            addr: w1 & !0xfff,
            am: extract_bits(w1, 5, 0) as u8,
        }
    }

    /// Encode to descriptor words.
    #[must_use]
    pub const fn to_words(&self) -> [u64; 2] {
        let w0 = type_bits(QiType::IOTLB.0)
            | (((self.granularity.bits()) as u64) << 4)
            | (((self.did) as u64) << 16);
        let w1 = (self.addr & !0xfff) | (self.am & 0x3f) as u64;
        [w0, w1]
    }
}

/// Device-TLB invalidate descriptor (128-bit, section 6.5.2.5).
///
/// Word 0: type, `SID` (47:32). Word 1: address (63:12), size `S` (0).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QiDevTlb {
    /// Source identifier of the device whose ATC is invalidated.
    pub sid: u16,
    /// Address to invalidate (page aligned).
    pub addr: u64,
    /// Size hint: `false` = 4 KiB, `true` = the device may flush a larger
    /// range.
    pub oversized: bool,
}

impl QiDevTlb {
    /// Build a descriptor.
    #[must_use]
    pub const fn new(sid: u16, addr: u64, oversized: bool) -> Self {
        QiDevTlb {
            sid,
            addr,
            oversized,
        }
    }

    /// Decode from descriptor words.
    #[must_use]
    pub const fn from_words(w0: u64, w1: u64) -> Self {
        QiDevTlb {
            sid: extract_bits(w0, 47, 32) as u16,
            addr: w1 & !0xfff,
            oversized: w1 & 1 != 0,
        }
    }

    /// Encode to descriptor words.
    #[must_use]
    pub const fn to_words(&self) -> [u64; 2] {
        let w0 = type_bits(QiType::DEVICE_TLB.0) | (((self.sid) as u64) << 32);
        let w1 = (self.addr & !0xfff) | (self.oversized as u8) as u64;
        [w0, w1]
    }
}

/// Interrupt entry cache invalidate descriptor (128-bit, section 6.5.2.8).
///
/// Word 0: type, `G` (bit 4), index mask `IM` (31:27), start index `IIDX`
/// (47:32).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QiIec {
    /// Global invalidation when set; otherwise index-selective.
    pub global: bool,
    /// First interrupt index to invalidate.
    pub start_index: u16,
    /// Index mask: invalidate `2^IM` contiguous entries.
    pub index_mask: u8,
}

impl QiIec {
    /// Build a descriptor.
    #[must_use]
    pub const fn new(global: bool, start_index: u16, index_mask: u8) -> Self {
        QiIec {
            global,
            start_index,
            index_mask,
        }
    }

    /// Decode from descriptor words.
    #[must_use]
    pub const fn from_words(w0: u64, _w1: u64) -> Self {
        QiIec {
            global: extract_bits(w0, 4, 4) != 0,
            start_index: extract_bits(w0, 47, 32) as u16,
            index_mask: extract_bits(w0, 31, 27) as u8,
        }
    }

    /// Encode to descriptor words.
    #[must_use]
    pub const fn to_words(&self) -> [u64; 2] {
        let w0 = type_bits(QiType::INTERRUPT_ENTRY_CACHE.0)
            | (((self.global as u8) as u64) << 4)
            | (((self.index_mask & 0x1f) as u64) << 27)
            | (((self.start_index) as u64) << 32);
        [w0, 0]
    }
}

/// Invalidation wait descriptor (128-bit, section 6.5.2.9).
///
/// Word 0: type, `IF` (4), `SW` (5), `FN` (6), status data (63:32).
/// Word 1: status address (63:3, 8-byte aligned).
///
/// * `IF` (bit 4): generate an invalidation completion *event*.
/// * `SW` (bit 5): write the completion **status data** to `status_addr`.
/// * `FN` (bit 6): fence — wait for all prior descriptors regardless of
///   ordering rules.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QiWait {
    /// Completion through invalidation completion event.
    pub interrupt_flag: bool,
    /// Completion through status-data write.
    pub status_write: bool,
    /// Fence semantics.
    pub fence: bool,
    /// Status data written on completion (when `status_write`).
    pub status_data: u32,
    /// Physical address of the status dword (8-byte aligned, bits 63:3).
    pub status_addr: u64,
}

impl QiWait {
    /// Build a status-write wait descriptor.
    #[must_use]
    pub const fn status_write(status_addr: u64, status_data: u32) -> Self {
        QiWait {
            interrupt_flag: false,
            status_write: true,
            fence: false,
            status_data,
            status_addr: status_addr & !0x7,
        }
    }

    /// Build a fence descriptor.
    #[must_use]
    pub const fn fence() -> Self {
        QiWait {
            interrupt_flag: false,
            status_write: false,
            fence: true,
            status_data: 0,
            status_addr: 0,
        }
    }

    /// Decode from descriptor words.
    #[must_use]
    pub const fn from_words(w0: u64, w1: u64) -> Self {
        QiWait {
            interrupt_flag: extract_bits(w0, 4, 4) != 0,
            status_write: extract_bits(w0, 5, 5) != 0,
            fence: extract_bits(w0, 6, 6) != 0,
            status_data: extract_bits(w0, 63, 32) as u32,
            status_addr: w1 & !0x7,
        }
    }

    /// Encode to descriptor words.
    #[must_use]
    pub const fn to_words(&self) -> [u64; 2] {
        let w0 = type_bits(QiType::WAIT.0)
            | (((self.interrupt_flag as u8) as u64) << 4)
            | (((self.status_write as u8) as u64) << 5)
            | (((self.fence as u8) as u64) << 6)
            | (((self.status_data) as u64) << 32);
        let w1 = self.status_addr & !0x7;
        [w0, w1]
    }
}

/// PASID-cache invalidate descriptor (128-bit form, section 6.5.2.2).
///
/// Word 0: type, `G` (5:4), `DID` (31:16), `PASID` (47:32). The descriptor
/// is architecturally 256-bit (word 2 carries the granular address); the
/// upper words are zero for global/domain invalidations.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QiPc {
    /// Invalidation granularity.
    pub granularity: Granularity,
    /// Domain identifier.
    pub did: u16,
    /// PASID to invalidate.
    pub pasid: u32,
}

impl QiPc {
    /// Build a descriptor.
    #[must_use]
    pub const fn new(granularity: Granularity, did: u16, pasid: u32) -> Self {
        QiPc {
            granularity,
            did,
            pasid,
        }
    }

    /// Decode from descriptor words.
    #[must_use]
    pub const fn from_words(w0: u64, _w1: u64) -> Self {
        QiPc {
            granularity: Granularity::from_bits(extract_bits(w0, 5, 4) as u8),
            did: extract_bits(w0, 31, 16) as u16,
            pasid: extract_bits(w0, 63, 32) as u32,
        }
    }

    /// Encode to descriptor words.
    #[must_use]
    pub const fn to_words(&self) -> [u64; 2] {
        let w0 = type_bits(QiType::PASID_CACHE.0)
            | (((self.granularity.bits()) as u64) << 4)
            | (((self.did) as u64) << 16)
            | (((self.pasid) as u64) << 32);
        [w0, 0]
    }
}

/// PASID-based IOTLB invalidate descriptor (128-bit, section 6.5.2.4).
///
/// Word 0: type, `G` (5:4), `DID` (31:16), `PASID` (63:32). Word 1:
/// address (63:12), `AM` (5:0).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QiPiotlb {
    /// Invalidation granularity.
    pub granularity: Granularity,
    /// Domain identifier.
    pub did: u16,
    /// PASID whose IOTLB entries are invalidated.
    pub pasid: u32,
    /// Guest physical address (page aligned).
    pub addr: u64,
    /// Address mask.
    pub am: u8,
}

impl QiPiotlb {
    /// Build a descriptor.
    #[must_use]
    pub const fn new(granularity: Granularity, did: u16, pasid: u32, addr: u64, am: u8) -> Self {
        QiPiotlb {
            granularity,
            did,
            pasid,
            addr,
            am,
        }
    }

    /// Decode from descriptor words.
    #[must_use]
    pub const fn from_words(w0: u64, w1: u64) -> Self {
        QiPiotlb {
            granularity: Granularity::from_bits(extract_bits(w0, 5, 4) as u8),
            did: extract_bits(w0, 31, 16) as u16,
            pasid: extract_bits(w0, 63, 32) as u32,
            addr: w1 & !0xfff,
            am: extract_bits(w1, 5, 0) as u8,
        }
    }

    /// Encode to descriptor words.
    #[must_use]
    pub const fn to_words(&self) -> [u64; 2] {
        let w0 = type_bits(QiType::PASID_IOTLB.0)
            | (((self.granularity.bits()) as u64) << 4)
            | (((self.did) as u64) << 16)
            | (((self.pasid) as u64) << 32);
        let w1 = (self.addr & !0xfff) | (self.am & 0x3f) as u64;
        [w0, w1]
    }
}

/// PASID-based device-TLB invalidate descriptor (256-bit, section 6.5.2.6).
///
/// Word 0: type, `G`/global (0), `PASID` (63:32). Word 1: address (63:12),
/// size (11). Word 2: `SID` (47:32), `PFSID` (63:48)? — see fields.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QiDevPiotlb {
    /// Invalidate all ATC entries for the PASID (global within PASID).
    pub global: bool,
    /// PASID.
    pub pasid: u32,
    /// Address to invalidate (page aligned).
    pub addr: u64,
    /// Size: `2^(S+1)` pages when set, single page otherwise.
    pub size_order: bool,
    /// Source identifier.
    pub sid: u16,
    /// Physical source identifier (SR-IOV VF alias).
    pub pfsid: u16,
}

impl QiDevPiotlb {
    /// Build a descriptor.
    #[must_use]
    pub const fn new(
        global: bool,
        pasid: u32,
        addr: u64,
        size_order: bool,
        sid: u16,
        pfsid: u16,
    ) -> Self {
        QiDevPiotlb {
            global,
            pasid,
            addr,
            size_order,
            sid,
            pfsid,
        }
    }

    /// Encode to descriptor words (returns words 0..2; word 3 is zero).
    #[must_use]
    pub const fn to_words4(&self) -> [u64; 4] {
        let w0 = type_bits(QiType::PASID_DEVICE_TLB.0)
            | ((self.global as u8) as u64)
            | (((self.pasid) as u64) << 32);
        let w1 = (self.addr & !0xfff) | (((self.size_order as u8) as u64) << 11);
        let w2 = (((self.sid) as u64) << 32) | (((self.pfsid) as u64) << 16);
        [w0, w1, w2, 0]
    }
}

/// One queued-invalidation descriptor of any shape.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QiDesc {
    /// Context-cache invalidate.
    ContextCache(QiCc),
    /// IOTLB invalidate.
    Iotlb(QiIotlb),
    /// Device-TLB invalidate.
    DevTlb(QiDevTlb),
    /// Interrupt entry cache invalidate.
    Iec(QiIec),
    /// Invalidation wait.
    Wait(QiWait),
    /// PASID-cache invalidate.
    PasidCache(QiPc),
    /// PASID-based IOTLB invalidate.
    PasidIotlb(QiPiotlb),
    /// PASID-based device-TLB invalidate (256-bit).
    PasidDevTlb(QiDevPiotlb),
}

impl QiDesc {
    /// Descriptor type code.
    #[must_use]
    pub const fn ty(&self) -> QiType {
        match self {
            QiDesc::ContextCache(_) => QiType::CONTEXT_CACHE,
            QiDesc::Iotlb(_) => QiType::IOTLB,
            QiDesc::DevTlb(_) => QiType::DEVICE_TLB,
            QiDesc::Iec(_) => QiType::INTERRUPT_ENTRY_CACHE,
            QiDesc::Wait(_) => QiType::WAIT,
            QiDesc::PasidCache(_) => QiType::PASID_CACHE,
            QiDesc::PasidIotlb(_) => QiType::PASID_IOTLB,
            QiDesc::PasidDevTlb(_) => QiType::PASID_DEVICE_TLB,
        }
    }

    /// Encode as two 64-bit words (128-bit form; for 256-bit descriptors
    /// such as [`QiDesc::PasidDevTlb`] the second word pair is lost — use
    /// [`QiDesc::words4`] instead).
    #[must_use]
    pub const fn words(&self) -> [u64; 2] {
        match self {
            QiDesc::ContextCache(d) => d.to_words(),
            QiDesc::Iotlb(d) => d.to_words(),
            QiDesc::DevTlb(d) => d.to_words(),
            QiDesc::Iec(d) => d.to_words(),
            QiDesc::Wait(d) => d.to_words(),
            QiDesc::PasidCache(d) => d.to_words(),
            QiDesc::PasidIotlb(d) => d.to_words(),
            // 256-bit descriptors cannot round-trip through two words;
            // encode zero so the queue slot is at least not misread.
            QiDesc::PasidDevTlb(_) => [0, 0],
        }
    }

    /// Encode as four 64-bit words (256-bit queue slot).
    #[must_use]
    pub const fn words4(&self) -> [u64; 4] {
        match self {
            QiDesc::PasidDevTlb(d) => d.to_words4(),
            other => {
                let w = other.words();
                [w[0], w[1], 0, 0]
            }
        }
    }

    /// Decode a 128-bit descriptor from raw words.
    #[must_use]
    pub const fn from_words(w0: u64, w1: u64) -> Option<Self> {
        match QiType::from_word0(w0) {
            QiType::CONTEXT_CACHE => Some(QiDesc::ContextCache(QiCc::from_words(w0, w1))),
            QiType::IOTLB => Some(QiDesc::Iotlb(QiIotlb::from_words(w0, w1))),
            QiType::DEVICE_TLB => Some(QiDesc::DevTlb(QiDevTlb::from_words(w0, w1))),
            QiType::INTERRUPT_ENTRY_CACHE => Some(QiDesc::Iec(QiIec::from_words(w0, w1))),
            QiType::WAIT => Some(QiDesc::Wait(QiWait::from_words(w0, w1))),
            QiType::PASID_CACHE => Some(QiDesc::PasidCache(QiPc::from_words(w0, w1))),
            QiType::PASID_IOTLB => Some(QiDesc::PasidIotlb(QiPiotlb::from_words(w0, w1))),
            _ => None,
        }
    }

    /// Number of 16-byte slots this descriptor occupies in the queue.
    #[must_use]
    pub const fn slot_count(&self) -> usize {
        match self {
            QiDesc::PasidDevTlb(_) => 2,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_encoding_roundtrip() {
        for t in [1u8, 2, 3, 4, 5, 6, 7, 8, 9] {
            let w0 = type_bits(t);
            assert_eq!(QiType::from_word0(w0), QiType(t), "type {t}");
        }
    }

    #[test]
    fn cc_descriptor_layout() {
        let d = QiDesc::ContextCache(QiCc::new(Granularity::PageOrDevice, 0x1234, 0xf00d, 1));
        let w = d.words();
        assert_eq!(QiType::from_word0(w[0]), QiType::CONTEXT_CACHE);
        assert_eq!(extract_bits(w[0], 5, 4), 3);
        assert_eq!((w[0] >> 16) & 0xffff, 0x1234);
        assert_eq!((w[0] >> 32) & 0xffff, 0xf00d);
        assert_eq!(extract_bits(w[0], 49, 48), 1);
        match QiDesc::from_words(w[0], w[1]) {
            Some(QiDesc::ContextCache(cc)) => {
                assert_eq!(cc.did, 0x1234);
                assert_eq!(cc.sid, 0xf00d);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn wait_descriptor_layout() {
        let d = QiWait::status_write(0x1000, 1);
        let [w0, w1] = d.to_words();
        assert_eq!(QiType::from_word0(w0), QiType::WAIT);
        assert_eq!(extract_bits(w0, 5, 5), 1);
        assert_eq!(w0 >> 32, 1); // status data
        assert_eq!(w1 & !0x7, 0x1000); // status address
    }

    #[test]
    fn iotlb_descriptor_layout() {
        let d = QiIotlb::new(Granularity::PageOrDevice, 9, 0xdead_beef_f000, 4);
        let [w0, w1] = d.to_words();
        assert_eq!(QiType::from_word0(w0), QiType::IOTLB);
        assert_eq!((w0 >> 16) & 0xffff, 9);
        assert_eq!(w1 & !0xfff, 0xdead_beef_f000);
        assert_eq!(w1 & 0x3f, 4);
    }
}
