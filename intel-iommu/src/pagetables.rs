//! First-stage and second-stage page tables.
//!
//! * **First-stage** tables (section 9.7) translate guest virtual addresses
//!   and follow the Intel-64 4-level (PML4/PDPT/PD/PT) or 5-level
//!   (PML5/PML4/PDPT/PD/PT) hierarchy with `RXW` present/permission bits,
//!   accessed/dirty bits and supertm hints.
//! * **Second-stage** tables (section 9.8) translate guest *physical*
//!   addresses and follow the EPT-like 4/5-level hierarchy (`SS-PML5` …
//!   `SS-PTE`) with `R/W/X`, accessed/dirty, and NxD semantics.
//!
//! The crate does not access memory itself: walkers take a `fetch` closure
//! mapping a physical table address to the next 64-bit entry. This keeps
//! the module allocation-free and usable from bare-metal, hypervisor and
//! emulator contexts.
//!
//! ```
//! use intel_iommu::pagetables::{self, Stage, Perm};
//!
//! // A 4-level second-stage tree: PML4 @ 0x1000 -> PDPT @ 0x2000 ->
//! // PD @ 0x3000 -> PT @ 0x4000, where PT[0] maps GPA 0 to
//! // HPA 0x1234_5000 as a 4 KiB read-write page. The fetch closure maps
//! // each table entry address to its current 64-bit value.
//! let fetch = |paddr: u64| -> u64 {
//!     match paddr {
//!         0x1000 => 0x2000 | Perm::RW.bits() | 1,
//!         0x2000 => 0x3000 | Perm::RW.bits() | 1,
//!         0x3000 => 0x4000 | Perm::RW.bits() | 1,
//!         0x4000 => 0x1234_5000 | Perm::RW.bits() | 1,
//!         _ => 0,
//!     }
//! };
//!
//! let r = pagetables::walk(Stage::Second, 4, 0x1000, 0x123, &fetch).unwrap();
//! assert_eq!(r.physical, 0x1234_5000 + 0x123); // frame | page offset
//! assert_eq!(r.level, 1);
//! assert!(r.perms.contains(Perm::RW));
//! ```
//!
//! For building tables from scratch use [`SecondStagePte`] together with
//! [`MapRange::leaves`].

use crate::bits::extract_bits;
use bitflags::bitflags;
use core::fmt;

/// Page-table hierarchy kind.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Stage {
    /// First-stage (guest virtual address) tables, sections 9.7.
    First,
    /// Second-stage (guest physical address) tables, sections 9.8.
    Second,
}

bitflags! {
    /// Permission and state bits carried by present page-table entries of
    /// both stages.
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct Perm: u64 {
        /// Read permission (R); also the present bit.
        const R = 1 << 0;
        /// Write permission (W).
        const W = 1 << 1;
        /// Execute permission (X); in first-stage tables this is the
        /// supervisor-entry (US=0) reserved position — hardware treats
        /// bit 2 as X only where execute permission is supported.
        const X = 1 << 2;
        /// Read + write.
        const RW = Self::R.bits() | Self::W.bits();
        /// Read + write + execute.
        const RWX = Self::R.bits() | Self::W.bits() | Self::X.bits();
        /// Huge-page / page-size flag (PS, bit 7).
        const PAGE_SIZE = 1 << 7;
        /// Accessed (A, bit 8).
        const ACCESSED = 1 << 8;
        /// Dirty (D, bit 9).
        const DIRTY = 1 << 9;
        /// Global (G, bit 10, first-stage).
        const GLOBAL = 1 << 10;
        /// Execute-disable (XD/NX, bit 63) — set means *no* execute.
        const EXECUTE_DISABLE = 1 << 63;
    }
}

impl Perm {
    /// Hardware `RXW` nibble (bits 2:0).
    #[must_use]
    pub const fn rxw(self) -> u8 {
        (self.bits() & 0x7) as u8
    }
}

/// Error returned by the page-table walker.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WalkError {
    /// A non-leaf entry was not present.
    NotPresent {
        /// Walk level at which the walk stopped (1 = leaf).
        level: u8,
    },
    /// The requested address exceeded the width covered by the table.
    AddressTooLarge {
        /// Address bits covered by the given number of levels.
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

/// Result of a successful page-table walk.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WalkResult {
    /// Resolved physical address (HPA for first-stage, HPA for second).
    pub physical: u64,
    /// Leaf level (1 = 4 KiB PTE, 2 = 2 MiB, 3 = 1 GiB).
    pub level: u8,
    /// Permissions of the leaf entry.
    pub perms: Perm,
    /// Whether the leaf is a super page (PS = 1).
    pub huge: bool,
}

/// Page sizes per leaf level (level 1 = 4 KiB).
const LEVEL_SHIFT: [u32; 5] = [12, 21, 30, 39, 48];

/// Walk a first- or second-stage page table for `vaddr`.
///
/// `levels` is 4 or 5; `root` is the physical address of the top-level
/// table (FS-PML4/FS-PML5 or SS-PML4/SS-PML5). `fetch` returns the entry
/// at a given physical table address — for indexes, the walker multiplies
/// by 8 and adds the index offset before calling `fetch`, so `fetch`
/// receives the *entry* address, not the table base.
pub fn walk<F>(stage: Stage, levels: u8, root: u64, vaddr: u64, fetch: &F) -> Result<WalkResult, WalkError>
where
    F: Fn(u64) -> u64,
{
    let top_shift = LEVEL_SHIFT[(levels - 1) as usize];
    let addr_bits = top_shift + 9;
    if vaddr >> addr_bits != 0 && stage == Stage::Second {
        return Err(WalkError::AddressTooLarge { bits: addr_bits });
    }
    let mut table = root;
    let mut level = levels;
    while level > 0 {
        let shift = LEVEL_SHIFT[(level - 1) as usize];
        let index = extract_bits(vaddr, (shift + 8) as u8, shift as u8);
        let entry = fetch(table + (index << 3));
        if entry & 1 == 0 {
            return Err(WalkError::NotPresent { level });
        }
        let perms = Perm::from_bits_truncate(entry);
        let ps = entry & (1 << 7) != 0;
        if ps || level == 1 {
            // Leaf: physical base comes from bits 51:12 of the entry.
            let base = entry & 0x000f_ffff_ffff_f000;
            let off_mask = (1u64 << shift) - 1;
            return Ok(WalkResult {
                physical: base | (vaddr & off_mask),
                level,
                perms,
                huge: ps && level > 1,
            });
        }
        table = entry & 0x000f_ffff_ffff_f000;
        level -= 1;
    }
    unreachable!("walker loop always returns at level 1");
}

/// A second-stage page-table entry (`SS-PTE` / `SS-PDE` …) as specified in
/// section 9.8.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SecondStagePte(pub u64);

impl SecondStagePte {
    /// Not-present entry.
    pub const EMPTY: SecondStagePte = SecondStagePte(0);

    /// Build a present leaf entry mapping `paddr` (4 KiB aligned) with
    /// `perms`.
    #[must_use]
    pub const fn page(paddr: u64, perms: Perm) -> Self {
        SecondStagePte((paddr & 0x000f_ffff_ffff_f000) | (perms.bits() & 0x3) | 1)
    }

    /// Build a present next-level (non-leaf) entry pointing at `next`
    /// table.
    #[must_use]
    pub const fn table(next: u64) -> Self {
        SecondStagePte((next & 0x000f_ffff_ffff_f000) | (Perm::R.bits() | Perm::W.bits() | Perm::X.bits()) | 1)
    }

    /// Build a present huge-page (leaf at level > 1) entry.
    #[must_use]
    pub const fn huge_page(paddr: u64, perms: Perm) -> Self {
        SecondStagePte(
            (paddr & 0x000f_ffff_ffff_f000)
                | (perms.bits() & 0x3)
                | Perm::PAGE_SIZE.bits()
                | 1,
        )
    }

    /// Raw entry value.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Present flag.
    #[must_use]
    pub const fn present(self) -> bool {
        self.0 & 1 != 0
    }

    /// Permissions (RXW + A/D/XD).
    #[must_use]
    pub const fn perms(self) -> Perm {
        Perm::from_bits_truncate(self.0)
    }

    /// Physical frame address (bits 51:12).
    #[must_use]
    pub const fn frame(self) -> u64 {
        self.0 & 0x000f_ffff_ffff_f000
    }

    /// Mark accessed/dirty.
    #[must_use]
    pub const fn with_accessed_dirty(self, accessed: bool, dirty: bool) -> Self {
        let mut v = self.0;
        if accessed {
            v |= Perm::ACCESSED.bits();
        }
        if dirty {
            v |= Perm::DIRTY.bits();
        }
        SecondStagePte(v)
    }
}

/// Index of `vaddr` at a given page-table level (0..511).
#[must_use]
pub const fn index_at(vaddr: u64, level: u8) -> usize {
    let shift = LEVEL_SHIFT[(level - 1) as usize];
    (extract_bits(vaddr, (shift + 8) as u8, shift as u8)) as usize
}

/// A mapping request consumed by the leaf iterator below.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MapRange {
    /// Guest address to map (GVA for first-stage, GPA for second).
    pub guest_base: u64,
    /// Host physical base of the backing pages.
    pub host_base: u64,
    /// Number of bytes to map (rounded up to 4 KiB pages).
    pub len: u64,
    /// Leaf permissions.
    pub perms: Perm,
}

impl MapRange {
    /// Compute the number of 4 KiB leaf entries needed.
    #[must_use]
    pub const fn page_count(&self) -> u64 {
        self.len.div_ceil(4096)
    }
}

/// Iterator over the 4 KiB leaf updates required to apply a mapping.
///
/// The crate leaves intermediate-table allocation to the caller (tables
/// may come from a page allocator, a fixed arena or an emulator's memory);
/// this iterator yields only the 4 KiB leaf updates.
///
/// The caller owns table storage; this helper yields `(entry_addr, pte)`
/// pairs for the *leaf* level and the caller is responsible for creating
/// intermediate tables (usually by mapping them all R/W/X present).
///
/// ```
/// use intel_iommu::pagetables::{MapRange, Perm};
///
/// let m = MapRange { guest_base: 0x1000, host_base: 0x9000, len: 0x3000, perms: Perm::R | Perm::W };
/// let mut n = 0;
/// for (gpa, hpa, pte) in m.leaves() {
///     let _ = (gpa, hpa, pte);
///     n += 1;
/// }
/// assert_eq!(n, 3);
/// ```
impl MapRange {
    /// Iterate `(guest_page, host_page, leaf_entry)` triples.
    pub fn leaves(&self) -> impl Iterator<Item = (u64, u64, SecondStagePte)> + '_ {
        let pages = self.page_count();
        (0..pages).map(move |i| {
            let g = self.guest_base + (i << 12);
            let h = self.host_base + (i << 12);
            (g, h, SecondStagePte::page(h, self.perms))
        })
    }
}

/// Build one first-stage leaf entry (Intel-64-like) for `vaddr` -> `paddr`.
///
/// First-stage entries share the Intel-64 format: P = R = bit 0, RW = bit
/// 1, US = bit 2, A/D bits 5/6, PS = bit 7, G = bit 8? — this helper sets
/// P/RW/US/A/D plus the frame, following the common kernel usage.
#[must_use]
pub const fn first_stage_leaf(paddr: u64, user: bool, writable: bool) -> u64 {
    let mut v = (paddr & 0x000f_ffff_ffff_f000)
        | Perm::ACCESSED.bits()
        | Perm::DIRTY.bits()
        | 1;
    if writable {
        v |= Perm::W.bits();
    }
    if user {
        v |= Perm::X.bits(); // US is bit 2 in Intel-64 layout
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Four-level table: PML4[0]->PDPT, PDPT[0]->1 GiB huge page.
    #[test]
    fn walks_huge_pages() {
        // The fetch closure answers one fixed entry per page-aligned table
        // address, mirroring how an emulator looks tables up.
        let fetch = |p: u64| match p {
            0x1000 => 0x2000 | Perm::RW.bits() | 1,
            0x2000 => 0x1_0000_0000u64 | Perm::RW.bits() | Perm::PAGE_SIZE.bits() | 1,
            _ => 0,
        };
        // vaddr inside the first 1 GiB so the PDPT index is 0.
        let r = walk(Stage::Second, 4, 0x1000, 0x1234_5000, &fetch).unwrap();
        assert_eq!(r.physical, 0x1_1234_5000);
        assert_eq!(r.level, 3);
        assert!(r.huge);
        assert!(r.perms.contains(Perm::RW));
    }

    #[test]
    fn not_present_is_reported() {
        let fetch = |_p: u64| 0u64;
        let e = walk(Stage::Second, 4, 0x1000, 0, &fetch).unwrap_err();
        assert_eq!(e, WalkError::NotPresent { level: 4 });
    }

    #[test]
    fn address_range_check() {
        let fetch = |_p: u64| 0u64;
        // 4-level second-stage covers 2^48 bytes; 2^48 must fail before
        // any table access.
        let e = walk(Stage::Second, 4, 0x1000, 1u64 << 48, &fetch).unwrap_err();
        assert_eq!(e, WalkError::AddressTooLarge { bits: 48 });
    }

    #[test]
    fn leaf_entries_hold_permissions() {
        let pte = SecondStagePte::page(0xabc000, Perm::R | Perm::W);
        assert!(pte.present());
        assert_eq!(pte.frame(), 0xabc000);
        assert!(pte.perms().contains(Perm::RW));
        let huge = SecondStagePte::huge_page(0x1_2345_0000, Perm::R);
        assert!(huge.0 & Perm::PAGE_SIZE.bits() != 0);
    }
}
