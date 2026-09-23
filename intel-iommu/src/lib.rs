//! # intel-iommu
//!
//! `no_std` library for **Intel VT-d** (Virtualization Technology for Directed
//! I/O), implementing the data-structure formats and register map of the
//! *Intel Virtualization Technology for Directed I/O Architecture
//! Specification* (Order D51397-019, rev. 5.20).
//!
//! The crate is a pure **format + register-map** library: it never performs
//! side effects, never allocates and contains no unsafe MMIO access of its
//! own. It is intended as the foundation for hypervisors, kernels, firmware
//! and emulators (e.g. QEMU-like device models) that drive or emulate VT-d
//! hardware.
//!
//! ## Layout
//!
//! | Module         | Content                                                              |
//! |----------------|----------------------------------------------------------------------|
//! | [`dmar`]       | ACPI DMAR table: DRHD/RMRR/ATSR/RHSA/ANDD/SATC/SIDP structures        |
//! | [`regs`]       | MMIO register offsets, `CAP`/`ECAP` decoding, GCMD/GSTS/CCMD/… words  |
//! | [`context`]    | Root/scalable-root, context/scalable-context, PASID directory/table   |
//! | [`qi`]         | Queued-invalidation descriptors (128-bit and 256-bit forms)           |
//! | [`fault`]      | Fault recording registers (primary fault logging)                     |
//! | [`irte`]       | Interrupt remapping table entries (remapped and posted forms)         |
//! | [`pagetables`] | First-stage (Intel-64 like) and second-stage (EPT-like) page tables   |
//!
//! ## Binary formats
//!
//! Every memory-resident hardware structure is expressed as a `#[repr(C)]`
//! zerocopy type: a hardware-visible layout can be interpreted without
//! copying via [`zerocopy::FromBytes::ref_from_bytes`]. Little-endian scalar
//! fields use [`zerocopy::byteorder::U16`]/[`U32`]/[`U64`] wrappers, so the
//! crate is endian-independent on the host side.
//!
//! ## Page-table walkers
//!
//! [`pagetables`] provides allocation-free, closure-driven walkers for
//! first-stage (4-level / 5-level) and second-stage (SS-PML5…SS-PTE)
//! translations. The caller supplies a fetch callback that maps a physical
//! address to a table entry, keeping the crate usable from bare-metal and
//! emulator contexts alike.
//!
//! ## Example
//!
//! Parse a DMAR table and enumerate DRHD units:
//!
//! ```
//! use intel_iommu::dmar::{DmarTable, RemapStruct};
//!
//! static DMAR: &[u8] = &[
//!     // Signature "DMAR"
//!     b'D', b'M', b'A', b'R',
//!     // Length = 48 (header only)
//!     48, 0, 0, 0,
//!     // Revision, Checksum (byte sum of the table is 0 mod 256)
//!     1, 55,
//!     // OEM ID, OEM Table ID
//!     b'O', b'E', b'M', b' ', b' ', b' ', 0, 0, 0, 0, 0, 0, 0, 0,
//!     // OEM Revision, Creator ID, Creator Revision
//!     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//!     // Host Address Width: bits 51:0 -> HAW 52
//!     52 - 1,
//!     // Flags
//!     0,
//!     // Reserved[10]
//!     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//! ];
//!
//! let dmar = DmarTable::new(DMAR).unwrap();
//! assert_eq!(dmar.host_address_width(), 52);
//! assert!(dmar.structs().next().is_none());
//! ```

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

pub mod context;
pub mod dmar;
pub mod fault;
pub mod irte;
pub mod pagetables;
pub mod qi;
pub mod regs;

mod bits;

pub use bits::{bits_of, extract_bits};
