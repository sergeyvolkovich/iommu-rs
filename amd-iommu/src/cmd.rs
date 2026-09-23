//! Command buffer entries — section 2.4.
//!
//! Each command is 128 bits (16 bytes): the opcode sits at bits `63:60`
//! (byte 4..8, high nibble) with the first opcode-dependent operand
//! filling the rest of that dword and bits `31:0` of dword 0.
//!
//! | Opcode | Command                    | Section |
//! |--------|----------------------------|---------|
//! | 01h    | COMPLETION_WAIT            | 2.4.1   |
//! | 02h    | INVALIDATE_DEVTAB_ENTRY    | 2.4.2   |
//! | 03h    | INVALIDATE_IOMMU_PAGES     | 2.4.3   |
//! | 04h    | INVALIDATE_IOTLB_PAGES     | 2.4.4   |
//! | 05h    | INVALIDATE_INTERRUPT_TABLE | 2.4.5   |
//! | 06h    | PREFETCH_IOMMU_PAGES       | 2.4.6   |
//! | 07h    | COMPLETE_PPR_REQUEST       | 2.4.7   |
//! | 08h    | INVALIDATE_IOMMU_ALL       | 2.4.8   |
//!
//! ```
//! use amd_iommu::cmd::{Command, CompletionWait};
//!
//! // Completion wait storing a semaphore value at 0x1234_5008.
//! let cmd = Command::CompletionWait(
//!     CompletionWait::new().with_store(0x1234_5008, 1),
//! );
//! let words: [u32; 4] = cmd.words();
//! assert_eq!((words[1] >> 28) & 0xf, 0x1); // opcode
//! assert_eq!(words[0] & 1, 1);             // s = store
//! assert_eq!(words[2], 1);                 // store data low
//! ```


/// Opcode values (section 2.4).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Opcode(pub u8);

impl Opcode {
    /// COMPLETION_WAIT.
    pub const COMPLETION_WAIT: Opcode = Opcode(0x01);
    /// INVALIDATE_DEVTAB_ENTRY.
    pub const INVALIDATE_DEVTAB_ENTRY: Opcode = Opcode(0x02);
    /// INVALIDATE_IOMMU_PAGES.
    pub const INVALIDATE_IOMMU_PAGES: Opcode = Opcode(0x03);
    /// INVALIDATE_IOTLB_PAGES.
    pub const INVALIDATE_IOTLB_PAGES: Opcode = Opcode(0x04);
    /// INVALIDATE_INTERRUPT_TABLE.
    pub const INVALIDATE_INTERRUPT_TABLE: Opcode = Opcode(0x05);
    /// PREFETCH_IOMMU_PAGES.
    pub const PREFETCH_IOMMU_PAGES: Opcode = Opcode(0x06);
    /// COMPLETE_PPR_REQUEST.
    pub const COMPLETE_PPR_REQUEST: Opcode = Opcode(0x07);
    /// INVALIDATE_IOMMU_ALL.
    pub const INVALIDATE_IOMMU_ALL: Opcode = Opcode(0x08);

    /// Extract the opcode from dword 1.
    #[must_use]
    pub const fn from_dword1(d: u32) -> Self {
        Opcode((d >> 28) as u8)
    }
}

/// COMPLETION_WAIT (section 2.4.1).
///
/// `s` (bit 0): write [`Self::store_data`] to [`Self::store_addr`];
/// `i` (bit 1): set `ComWaitInt` in the status register;
/// `f` (bit 2): strict in-order queue flush.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CompletionWait {
    /// Store completion status to memory.
    pub store: bool,
    /// Raise the completion-wait interrupt.
    pub interrupt: bool,
    /// Flush: strictly ordered execution.
    pub flush: bool,
    /// 8-byte aligned store address (bits 51:3).
    pub store_addr: u64,
    /// 64-bit value stored on completion.
    pub store_data: u64,
}

impl CompletionWait {
    /// Build a store-based completion wait.
    #[must_use]
    pub const fn new() -> Self {
        CompletionWait {
            store: false,
            interrupt: false,
            flush: false,
            store_addr: 0,
            store_data: 0,
        }
    }

    /// Configure a semaphore store.
    #[must_use]
    pub const fn with_store(mut self, addr: u64, data: u64) -> Self {
        self.store = true;
        self.store_addr = addr & !0x7;
        self.store_data = data;
        self
    }

    /// Configure a strict fence.
    #[must_use]
    pub const fn with_flush(mut self) -> Self {
        self.flush = true;
        self
    }

    /// Configure the completion interrupt.
    #[must_use]
    pub const fn with_interrupt(mut self) -> Self {
        self.interrupt = true;
        self
    }

    /// Encode into the four dwords of the command entry.
    #[must_use]
    pub const fn encode(&self) -> [u32; 4] {
        let d0 = (self.store as u32)
            | ((self.interrupt as u32) << 1)
            | ((self.flush as u32) << 2)
            | (((self.store_addr >> 3) as u32 & 0x1fff_ffff) << 3);
        let d1 = (Opcode::COMPLETION_WAIT.0 as u32) << 28
            | (((self.store_addr >> 32) as u32) & 0xf_ffff);
        [d0, d1, self.store_data as u32, (self.store_data >> 32) as u32]
    }
}

/// INVALIDATE_DEVTAB_ENTRY (section 2.4.2).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct InvalidateDevTabEntry {
    /// DeviceID whose cached DTE must be reloaded.
    pub device_id: u16,
}

impl InvalidateDevTabEntry {
    /// Encode into (dword0, dword1).
    #[must_use]
    pub const fn encode(&self) -> (u32, u32) {
        (self.device_id as u32, (Opcode::INVALIDATE_DEVTAB_ENTRY.0 as u32) << 28)
    }
}

/// INVALIDATE_IOMMU_PAGES (section 2.4.3, figure 46).
///
/// * dword 0: `PASID[19:0]` (ignored when GN = 0).
/// * dword 1: opcode (31:28), `DomainID` (15:0).
/// * dword 2: `Address[31:12]` (31:12), `GN` (2), `PDE` (1), `S` (0).
/// * dword 3: `Address[63:32]`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct InvalidateIommuPages {
    /// Domain identifier.
    pub domain_id: u16,
    /// PASID (only meaningful with `gn`).
    pub pasid: u32,
    /// Page address to invalidate (bits 63:12).
    pub addr: u64,
    /// `S`: super-page invalidate.
    pub size: bool,
    /// `PDE`: address is a page-directory entry.
    pub pde: bool,
    /// `GN`: address is a GVA (guest nested).
    pub guest_nested: bool,
}

impl InvalidateIommuPages {
    /// Encode into the four dwords of the command entry.
    #[must_use]
    pub const fn encode(&self) -> [u32; 4] {
        let d0 = self.pasid & 0xf_ffff;
        let d1 = (Opcode::INVALIDATE_IOMMU_PAGES.0 as u32) << 28 | self.domain_id as u32;
        let d2 = (((self.addr >> 12) as u32) & 0xf_ffff) << 12
            | ((self.guest_nested as u32) << 2)
            | ((self.pde as u32) << 1)
            | (self.size as u32);
        let d3 = (self.addr >> 32) as u32;
        [d0, d1, d2, d3]
    }
}

/// INVALIDATE_IOTLB_PAGES (section 2.4.4, figure 47).
///
/// * dword 0: `Maxpend[7:0]` (31:24), `PASID[15:8]` (23:16),
///   `DeviceID` (15:0).
/// * dword 1: opcode (31:28), `PASID[19:16]` (27:24), `PASID[7:0]`
///   (23:16), `QueueID` (15:0).
/// * dword 2: `Address[31:12]` (31:12), `Type` (5:4), `GN` (2), `S` (0).
/// * dword 3: `Address[63:32]`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct InvalidateIotlbPages {
    /// Device whose ATC is invalidated.
    pub device_id: u16,
    /// Queue id shared by virtual functions.
    pub queue_id: u16,
    /// PASID (only meaningful with `gn`).
    pub pasid: u32,
    /// Max in-flight invalidations for this queue.
    pub max_pend: u8,
    /// Page address to invalidate.
    pub addr: u64,
    /// Invalidation type (00b standard; 01b/10b flush variants).
    pub inv_type: u8,
    /// `S`: super-page invalidate.
    pub size: bool,
    /// `GN`: address is a GVA.
    pub guest_nested: bool,
}

impl InvalidateIotlbPages {
    /// Encode into the four dwords of the command entry.
    #[must_use]
    pub const fn encode(&self) -> [u32; 4] {
        let d0 = (self.device_id as u32)
            | ((self.pasid >> 8) & 0xff) << 16
            | ((self.max_pend as u32) << 24);
        let d1 = (Opcode::INVALIDATE_IOTLB_PAGES.0 as u32) << 28
            | ((self.pasid >> 16) & 0xf) << 24
            | ((self.pasid & 0xff) << 16)
            | self.queue_id as u32;
        let d2 = (((self.addr >> 12) as u32) & 0xf_ffff) << 12
            | (((self.inv_type & 0x3) as u32) << 4)
            | ((self.guest_nested as u32) << 2)
            | (self.size as u32);
        let d3 = (self.addr >> 32) as u32;
        [d0, d1, d2, d3]
    }
}

/// COMPLETE_PPR_REQUEST (section 2.4.7).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CompletePprRequest {
    /// DeviceID of the requesting device.
    pub device_id: u16,
    /// PPR tag from the log entry.
    pub ppr_tag: u16,
    /// PASID of the request.
    pub pasid: u16,
}

impl CompletePprRequest {
    /// Encode into (dword0, dword1).
    #[must_use]
    pub const fn encode(&self) -> (u32, u32) {
        let d0 = (self.device_id as u32) | ((self.ppr_tag as u32) << 16);
        let d1 = (Opcode::COMPLETE_PPR_REQUEST.0 as u32) << 28 | (self.pasid as u32);
        (d0, d1)
    }
}

/// One command buffer entry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Serialize with command processing.
    CompletionWait(CompletionWait),
    /// Reload a cached device-table entry.
    InvalidateDevTabEntry(InvalidateDevTabEntry),
    /// Invalidate IOMMU page-table cache pages.
    InvalidateIommuPages(InvalidateIommuPages),
    /// Invalidate IOTLB (device IOTLB) pages.
    InvalidateIotlbPages(InvalidateIotlbPages),
    /// Invalidate a device's interrupt remapping table.
    InvalidateInterruptTable(InvalidateDevTabEntry),
    /// Complete a peripheral page request.
    CompletePprRequest(CompletePprRequest),
    /// Invalidate all cached translations.
    InvalidateIommuAll,
}

impl Command {
    /// Opcode of the command.
    #[must_use]
    pub const fn opcode(&self) -> Opcode {
        match self {
            Command::CompletionWait(_) => Opcode::COMPLETION_WAIT,
            Command::InvalidateDevTabEntry(_) => Opcode::INVALIDATE_DEVTAB_ENTRY,
            Command::InvalidateIommuPages(_) => Opcode::INVALIDATE_IOMMU_PAGES,
            Command::InvalidateIotlbPages(_) => Opcode::INVALIDATE_IOTLB_PAGES,
            Command::InvalidateInterruptTable(_) => Opcode::INVALIDATE_INTERRUPT_TABLE,
            Command::CompletePprRequest(_) => Opcode::COMPLETE_PPR_REQUEST,
            Command::InvalidateIommuAll => Opcode::INVALIDATE_IOMMU_ALL,
        }
    }

    /// Encode as four 32-bit dwords (`+00`, `+04`, `+08`, `+0C`).
    #[must_use]
    pub const fn words(&self) -> [u32; 4] {
        match self {
            Command::CompletionWait(c) => c.encode(),
            Command::InvalidateDevTabEntry(c) => {
                let (d0, d1) = c.encode();
                [d0, d1, 0, 0]
            }
            Command::InvalidateIommuPages(c) => c.encode(),
            Command::InvalidateIotlbPages(c) => c.encode(),
            Command::InvalidateInterruptTable(c) => {
                let (d0, d1) = c.encode();
                [d0, d1, 0, 0]
            }
            Command::CompletePprRequest(c) => {
                let (d0, d1) = c.encode();
                [d0, d1, 0, 0]
            }
            Command::InvalidateIommuAll => {
                [0, (Opcode::INVALIDATE_IOMMU_ALL.0 as u32) << 28, 0, 0]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_wait_encoding() {
        let cmd = Command::CompletionWait(CompletionWait::new().with_store(0x1_2345_6008, 1));
        let w = cmd.words();
        assert_eq!(Opcode::from_dword1(w[1]), Opcode::COMPLETION_WAIT);
        assert_eq!(w[0] & 0x7, 0x1); // s=1
        // store addr bits 31:3 in dword0[31:3]
        assert_eq!(
            (w[0] >> 3) & 0x1fff_ffff,
            (0x1_2345_6008u64 >> 3) as u32 & 0x1fff_ffff
        );
        // store addr bits 51:32 in dword1[19:0]
        assert_eq!(w[1] & 0xf_ffff, 0x1);
        assert_eq!(w[2], 1);
    }

    #[test]
    fn invalidate_pages_encoding() {
        let c = InvalidateIommuPages {
            domain_id: 7,
            addr: 0xdead_b000,
            pde: true,
            ..InvalidateIommuPages::default()
        };
        let w = Command::InvalidateIommuPages(c).words();
        assert_eq!(Opcode::from_dword1(w[1]), Opcode::INVALIDATE_IOMMU_PAGES);
        assert_eq!(w[1] & 0xffff, 7);
        assert_eq!(w[2] & 0x7, 0x2); // PDE only
        assert_eq!((w[2] >> 12) & 0xf_ffff, (0xdead_b000 >> 12) & 0xf_ffff);
        assert_eq!(w[3], 0);
    }

    #[test]
    fn invalidate_iotlb_pages_encoding() {
        let c = InvalidateIotlbPages {
            device_id: 0x1234,
            queue_id: 0x99,
            pasid: 0x5_a5a5,
            max_pend: 0x10,
            addr: 0x1_2345_6000,
            ..InvalidateIotlbPages::default()
        };
        let w = Command::InvalidateIotlbPages(c).words();
        assert_eq!(Opcode::from_dword1(w[1]), Opcode::INVALIDATE_IOTLB_PAGES);
        assert_eq!(w[0] & 0xffff, 0x1234);
        assert_eq!((w[0] >> 16) & 0xff, 0xa5); // PASID[15:8]
        assert_eq!((w[0] >> 24) & 0xff, 0x10); // Maxpend
        assert_eq!(w[1] & 0xffff, 0x99); // QueueID
        assert_eq!((w[1] >> 16) & 0xff, 0xa5); // PASID[7:0]
        assert_eq!((w[1] >> 24) & 0xf, 0x5); // PASID[19:16]
        assert_eq!((w[2] >> 12) & 0xf_ffff, 0x2_3456);
    }
}
