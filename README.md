# iommu-rs

Two `no_std` Rust crates for driving and emulating x86 IOMMUs:

| Crate | Hardware | Specification |
|-------|----------|---------------|
| [`amd-iommu`](amd-iommu) | AMD I/O Virtualization Technology (AMD-Vi) | 48882-PUB, rev. 3.11 (Apr 2026) |
| [`intel-iommu`](intel-iommu) | Intel VT-d (Directed I/O) | D51397-019, rev. 5.20 (Apr 2026) |

Both crates are pure **format + register-map** libraries: no allocation, no
side effects, no unsafe MMIO access of their own. They are intended as
foundations for hypervisors, kernels, firmware and emulators.

## Shared design

- **zerocopy** `#[repr(C)]` overlays for every memory-resident hardware
  structure (root/context/PASID tables, device table, invalidation
  descriptors, fault/PPR/event records, interrupt remap tables).
- **bitflags 2** for register and permission bits.
- **tock-registers** typed view of the VT-d MMIO register block.
- **thiserror** (no_std) error types, **log** facade for diagnostics.
- Closure-driven, allocation-free **page-table walkers** — the caller maps
  a physical table address to the next entry, so the same code works on
  bare metal, in a hypervisor, or inside an emulator.

## Crate coverage

### amd-iommu
- ACPI **IVRS** parsing (IVHD types 10h/11h/40h, IVMD, 4/8-byte and
  variable device entries)
- **Device Table Entry** — full 256-bit field map, GCR3 repacking, guest
  identifiers, interrupt remapping controls
- MMIO register map: buffer base encodings (`2^(N+4)` bytes / `2^(N+1)`
  entries), Control/Status bitflags
- Command buffer: COMPLETION_WAIT, INVALIDATE_DEVTAB_ENTRY,
  INVALIDATE_IOMMU_PAGES, INVALIDATE_IOTLB_PAGES,
  INVALIDATE_INTERRUPT_TABLE, COMPLETE_PPR_REQUEST, INVALIDATE_IOMMU_ALL
- Event log (IO_PAGE_FAULT decode + raw passthrough) and PPR log entries
- Interrupt remapping table entry (basic 128-bit format)
- IOMMU **v1 and v2** page tables (v1 IR/IW layout, v2 AMD64 layout) with
  huge-page support

### intel-iommu
- ACPI **DMAR** parsing with all seven remapping structures
  (DRHD/RMRR/ATSR/RHSA/ANDD/SATC/SIDP) and device scopes
- MMIO register map: offsets, `CAP`/`ECAP` decoders, GCMD/GSTS/CCMD/IQA/
  IRTA/IVA/IOTLB word builders, tock-registers block view
- Legacy and **scalable** root/context entries, PASID directory, 512-bit
  PASID table entries (PGTT, FLPM, SRE/WPE/EAFE, HPT fields)
- Queued invalidation: all descriptor types (context-cache, IOTLB,
  device-TLB, IEC, wait/fence, PASID-cache, PASID-IOTLB, 256-bit
  PASID-device-TLB)
- Fault recording registers with fault-reason catalogue
- Interrupt remapping table entries: remapped and posted (PDA split
  across both words)
- **First-stage** (4/5-level) and **second-stage** page-table walkers with
  huge pages and accessed/dirty bits

## Example

```rust
use intel_iommu::dmar::{DmarTable, RemapStruct};

let dmar = DmarTable::new(raw_acpi_table)?;
for drhd in dmar.drhd_units() {
    println!("VT-d unit at {:#x}, segment {}", drhd.register_base(), drhd.segment());
}
```

## Building and testing

```sh
cargo build --workspace
cargo test  --workspace   # 39 unit tests + 17 doctests
cargo clippy --workspace --all-targets
```

Both crates are `#![no_std]`; the optional `std` feature adds
`std::error::Error` implementations.

## Sources

Layouts were cross-verified against the vendor specifications (AMD
48882 rev 3.11, Intel VT-d rev 5.20), Linux `drivers/iommu`
(`amd_iommu_types.h`, `intel_pasid.h`) and QEMU
(`hw/i386/{amd,intel}_iommu*`).
