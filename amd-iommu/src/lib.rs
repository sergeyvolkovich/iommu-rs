//! # amd-iommu
//!
//! `no_std` library for the **AMD I/O Virtualization Technology (IOMMU,
//! AMD-Vi)**, implementing the data-structure formats, ACPI IVRS parsing
//! and MMIO register map of the *AMD I/O Virtualization Technology
//! (IOMMU) Specification* (48882-PUB, rev. 3.11, Apr 2026).
//!
//! The crate is a pure **format + register-map** library: no allocation, no
//! side effects, no unsafe MMIO access of its own. It is intended as the
//! foundation for hypervisors, kernels, firmware and emulators that drive
//! or emulate AMD-Vi hardware.
//!
//! ## Layout
//!
//! | Module         | Content                                                        |
//! |----------------|----------------------------------------------------------------|
//! | [`ivrs`]       | ACPI IVRS table: IVHD (types 10h/11h/40h), IVMD, device entries |
//! | [`dte`]        | Device Table Entry (256 bits, full field map)                   |
//! | [`regs`]       | MMIO register offsets, control/status registers, buffer bases   |
//! | [`cmd`]        | Command buffer entries (opcodes 01h–08h)                        |
//! | [`events`]     | Event log entries (event codes 1h–9h, Dh, Eh)                   |
//! | [`ppr`]        | Peripheral page request (PPR) log entries                       |
//! | [`irte`]       | Interrupt remapping table entries (basic format)                |
//! | [`pagetables`] | IOMMU v1 and v2 page tables with closure-driven walkers         |
//!
//! ## Binary formats
//!
//! Memory-resident structures are plain `#[repr(C)]` wrappers over
//! little-endian words and can be overlayed with
//! `zerocopy::FromBytes::ref_from_bytes` on little-endian targets.
//!
//! ## Example
//!
//! Build a Device Table Entry mapping a device to a v2 (AMD64) page table:
//!
//! ```
//! use amd_iommu::dte::{DeviceTableEntry, PagingMode};
//!
//! let dte = DeviceTableEntry::new()
//!     .with_valid(true)
//!     .with_translation_valid(true)
//!     .with_paging_mode(PagingMode::Level2_4)
//!     .with_host_page_table_root(0x1234_5000);
//!
//! assert!(dte.valid());
//! assert_eq!(dte.host_page_table_root(), 0x1234_5000);
//! ```

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

mod bits;

pub use bits::extract_bits;

pub mod cmd;
pub mod dte;
pub mod events;
pub mod irte;
pub mod ivrs;
pub mod pagetables;
pub mod ppr;
pub mod regs;
