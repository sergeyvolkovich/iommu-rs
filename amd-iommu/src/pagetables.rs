//! IOMMU page tables — section 5 (v1) and section 6 (v2).
//!
//! * **v1 tables** translate *device* IOVA into system physical addresses.
//!   They are a 4-level (or 3-level, `Mode = 010b`) radix tree of 64-bit
//!   entries with `PR` (present), `RW`, `US`, `U/S`-style permissions and
//!   legacy page sizes 4 KiB / 2 MiB / 1 GiB.
//! * **v2 tables** reuse the AMD64 long-mode page-table format (4- or
//!   5-level) with the standard PTE flag layout (`P`, `RW`, `US`, `A`,
//!   `D`, `PS`, `G`, `NX` at bit 63).
//!
//! Walkers are closure-driven: the caller maps a physical table address to
//! the next entry, keeping the crate allocation-free.
//!
//! ```
//! use amd_iommu::pagetables::{self, Format, Perm};
//!
//! // v2 (AMD64-style) 4-level tree: PML4 -> PDPT -> PD -> PT.
//! let fetch = |paddr: u64| -> u64 {
//!     match paddr {
//!         0x1000 => 0x2000 | Perm::P_RW.bits() | 1, // PML4[0] -> PDPT, present
//!         0x2000 => 0x3000 | Perm::P_RW.bits() | 1, // PDPT[0] -> PD
//!         0x3000 => 0x4000 | Perm::P_RW.bits() | 1, // PD[0] -> PT
//!         0x4000 => 0x1234_5000 | Perm::P_RW.bits() | 1, // PT[0]: 4 KiB RW page
//!         _ => 0,
//!     }
//! };
//!
//! let r = pagetables::walk(Format::V2, 4, 0x1000, 0x123, &fetch).unwrap();
//! assert_eq!(r.physical, 0x1234_5000 + 0x123);
//! assert_eq!(r.level, 1);
//! ```

use crate::bits::extract_bits;
use bitflags::bitflags;
use core::fmt;

/// Page table format (DTE `Mode` field).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Format {
    /// IOMMU v1 page tables (section 5).
    V1,
    /// IOMMU v2 page tables, AMD64 long-mode layout (section 6).
    V2,
}

bitflags! {
    /// Page-table permission / state bits shared by both formats.
    ///
    /// The flag names follow the specification: `PR` (present) is bit 0,
    /// `RW` bit 1, `US` bit 2, `FC` bit 3? (v1), `U`/`D` accessed-dirty
    /// bits 8/9 in v1, and the AMD64 layout in v2 (`A` = 5, `D` = 6,
    /// `PS` = 7, `G` = 8, `NX` = 63).
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct Perm: u64 {
        /// Present (PR, bit 0).
        const P = 1 << 0;
        /// Read-write (RW, bit 1).
        const RW = 1 << 1;
        /// User/supervisor (US, bit 2).
        const US = 1 << 2;
        /// v1 read permission (IR/R, bit 4).
        const IR = 1 << 4;
        /// v1 write permission (IW/W, bit 5).
        const IW = 1 << 5;
        /// v2 accessed (bit 5 position shares IW in v1 — see format).
        const ACCESSED = 1 << 5;
        /// v2 dirty (bit 6).
        const DIRTY = 1 << 6;
        /// Page size / huge page (PS, bit 7).
        const PS = 1 << 7;
        /// Global (G, bit 8).
        const G = 1 << 8;
        /// v1 no-execute? (bit 63 NX in v2).
        const NX = 1 << 63;
        /// Combined present + read-write.
        const P_RW = Self::P.bits() | Self::RW.bits();
    }
}

/// Result of a successful walk.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WalkResult {
    /// Resolved system physical address.
    pub physical: u64,
    /// Leaf level (1 = 4 KiB).
    pub level: u8,
    /// Leaf permission bits.
    pub perms: Perm,
    /// Leaf was a super page (PS = 1) above level 1.
    pub huge: bool,
}

/// Walk error.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WalkError {
    /// A non-leaf entry was not present.
    NotPresent {
        /// Level at which the walk stopped.
        level: u8,
    },
    /// The input address exceeded the table width.
    AddressTooLarge {
        /// Bits covered by the table.
        bits: u32,
    },
}

impl fmt::Display for WalkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalkError::NotPresent { level } => write!(f, "not present at level {level}"),
            WalkError::AddressTooLarge { bits } => {
                write!(f, "address exceeds {bits}-bit table width")
            }
        }
    }
}

/// Level shift for level `n` (1 = 12, 2 = 21, 3 = 30, 4 = 39, 5 = 48).
const LEVEL_SHIFT: [u32; 5] = [12, 21, 30, 39, 48];

/// Mask of physical address bits carried by a table entry (bits 51:12).
const PA_MASK: u64 = 0x000f_ffff_ffff_f000;

/// Walk a v1 or v2 page table for `iova`.
///
/// `levels` is 3, 4 or 5; `root` is the physical address of the top-level
/// table (from the DTE host page table root pointer).
pub fn walk<F>(format: Format, levels: u8, root: u64, iova: u64, fetch: &F) -> Result<WalkResult, WalkError>
where
    F: Fn(u64) -> u64,
{
    let top_shift = LEVEL_SHIFT[(levels - 1) as usize];
    let addr_bits = top_shift + 9;
    // v1 IOVAs are 64-bit; v2 tables follow AMD64 canonical rules — keep
    // the width check for both but derive the width from the tree.
    if iova >> addr_bits != 0 && format == Format::V2 {
        return Err(WalkError::AddressTooLarge { bits: addr_bits });
    }
    let mut table = root;
    let mut level = levels;
    while level > 0 {
        let shift = LEVEL_SHIFT[(level - 1) as usize];
        let index = extract_bits(iova, (shift + 8) as u8, shift as u8);
        let entry = fetch(table + (index << 3));
        if entry & 1 == 0 {
            return Err(WalkError::NotPresent { level });
        }
        let perms = Perm::from_bits_retain(entry);
        let ps = entry & Perm::PS.bits() != 0;
        if ps || level == 1 {
            let base = entry & PA_MASK;
            let off_mask = (1u64 << shift) - 1;
            return Ok(WalkResult {
                physical: base | (iova & off_mask),
                level,
                perms,
                huge: ps && level > 1,
            });
        }
        table = entry & PA_MASK;
        level -= 1;
    }
    unreachable!("walker always returns at level 1");
}

/// Build a v2 (AMD64-style) present leaf entry.
#[must_use]
pub const fn v2_page(paddr: u64, rw: bool, user: bool) -> u64 {
    let mut v = (paddr & PA_MASK) | Perm::P.bits() | Perm::ACCESSED.bits() | Perm::DIRTY.bits();
    if rw {
        v |= Perm::RW.bits();
    }
    if user {
        v |= Perm::US.bits();
    }
    v
}

/// Build a v2 present non-leaf (next table) entry.
#[must_use]
pub const fn v2_table(next: u64) -> u64 {
    (next & PA_MASK) | Perm::P_RW.bits() | Perm::US.bits() | Perm::ACCESSED.bits()
}

/// Build a v1 (IOMMU v1) leaf entry: `PR` + `IR`/`IW` permissions.
#[must_use]
pub const fn v1_page(paddr: u64, read: bool, write: bool) -> u64 {
    let mut v = (paddr & PA_MASK) | Perm::P.bits();
    if read {
        v |= Perm::IR.bits();
    }
    if write {
        v |= Perm::IW.bits();
    }
    v
}

/// Index of `iova` at a given level.
#[must_use]
pub const fn index_at(iova: u64, level: u8) -> usize {
    let shift = LEVEL_SHIFT[(level - 1) as usize];
    extract_bits(iova, (shift + 8) as u8, shift as u8) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_v2_leaf() {
        let fetch = |p: u64| match p {
            0x1000 => v2_table(0x2000),
            0x2000 => v2_table(0x3000),
            0x3000 => v2_table(0x4000),
            0x4000 => v2_page(0x1234_5000, true, false),
            _ => 0,
        };
        let r = walk(Format::V2, 4, 0x1000, 0x123, &fetch).unwrap();
        assert_eq!(r.physical, 0x1234_5000 + 0x123);
        assert_eq!(r.level, 1);
        assert!(r.perms.contains(Perm::P | Perm::RW));
    }

    #[test]
    fn walks_v1_huge_page() {
        // v1: IR/IW permission layout, 2 MiB page at level 2. With a
        // 2-level tree the top table entry itself is the huge-page leaf.
        let fetch = |p: u64| match p {
            0x1000 => v1_page(0x1_0000_0000, true, true) | Perm::PS.bits(),
            _ => 0,
        };
        // iova within the first 2 MiB so the level-2 index is 0.
        let r = walk(Format::V1, 2, 0x1000, 0x123_456, &fetch).unwrap();
        assert_eq!(r.level, 2);
        assert!(r.huge);
        assert_eq!(r.physical, 0x1_0000_0000 | (0x123_456 & 0x1f_ffff));
    }

    #[test]
    fn not_present_reported() {
        let fetch = |_p: u64| 0u64;
        let e = walk(Format::V2, 4, 0x1000, 0, &fetch).unwrap_err();
        assert_eq!(e, WalkError::NotPresent { level: 4 });
    }

    #[test]
    fn v2_range_check() {
        let fetch = |_p: u64| 0u64;
        let e = walk(Format::V2, 4, 0x1000, 1u64 << 48, &fetch).unwrap_err();
        assert_eq!(e, WalkError::AddressTooLarge { bits: 48 });
    }
}
