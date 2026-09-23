//! Event log entries — section 2.5.
//!
//! Event log entries are 128 bits. Dword 0 carries the DeviceID (15:0)
//! and 12 flag bits (27:16); dword 1 carries the event code (31:28) and,
//! for fault events, the 20-bit domain id (19:0); dwords 2/3 carry the
//! faulting address.
//!
//! ```
//! use amd_iommu::events::{Event, EventCode, PageFaultEvent};
//!
//! let pf = PageFaultEvent {
//!     device_id: 0x1234,
//!     domain_id: 5,
//!     addr: 0xdead_b000,
//!     write: true,
//!     ..PageFaultEvent::default()
//! };
//! let words = Event::PageFault(pf).words();
//! assert_eq!((words[1] >> 28) & 0xf, 0x2); // IO_PAGE_FAULT
//! assert_eq!(words[0] & 0xffff, 0x1234);
//! ```

/// Event codes (section 2.5, table 33).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EventCode(pub u8);

impl EventCode {
    /// ILLEGAL_DEVICE_EVENT.
    pub const ILLEGAL_DEVICE: EventCode = EventCode(0x1);
    /// IO_PAGE_FAULT.
    pub const IO_PAGE_FAULT: EventCode = EventCode(0x2);
    /// DEV_TAB_HARDWARE_ERROR.
    pub const DEV_TAB_HARDWARE_ERROR: EventCode = EventCode(0x3);
    /// PAGE_TAB_HARDWARE_ERROR.
    pub const PAGE_TAB_HARDWARE_ERROR: EventCode = EventCode(0x4);
    /// ILLEGAL_COMMAND_ERROR.
    pub const ILLEGAL_COMMAND_ERROR: EventCode = EventCode(0x5);
    /// COMMAND_HARDWARE_ERROR.
    pub const COMMAND_HARDWARE_ERROR: EventCode = EventCode(0x6);
    /// IOTLB_INV_TIMEOUT.
    pub const IOTLB_INV_TIMEOUT: EventCode = EventCode(0x7);
    /// INVALID_DEVICE_REQUEST.
    pub const INVALID_DEVICE_REQUEST: EventCode = EventCode(0x8);
    /// INVALID_PPR_REQUEST.
    pub const INVALID_PPR_REQUEST: EventCode = EventCode(0x9);
    /// RMP_FAULT (SEV-SNP).
    pub const RMP_FAULT: EventCode = EventCode(0xd);
    /// RMP_HARDWARE_ERROR (SEV-SNP).
    pub const RMP_HARDWARE_ERROR: EventCode = EventCode(0xe);

    /// Extract from dword 1.
    #[must_use]
    pub const fn from_dword1(d: u32) -> Self {
        EventCode((d >> 28) as u8)
    }
}

/// IO_PAGE_FAULT event payload (section 2.5.2).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PageFaultEvent {
    /// DeviceID of the faulting device.
    pub device_id: u16,
    /// Domain id (20 bits across dword 1).
    pub domain_id: u32,
    /// Faulting address.
    pub addr: u64,
    /// RW flag: transaction was a write.
    pub write: bool,
    /// PR flag: permission violation.
    pub permission: bool,
    /// RS flag: reserved bit violation.
    pub reserved: bool,
    /// RZ flag: translate-request with PASID zero.
    pub rz: bool,
    /// NX flag: no-execute violation.
    pub nx: bool,
    /// GN flag: guest nested (GPA address).
    pub guest_nested: bool,
    /// TR flag: translation request.
    pub translation: bool,
    /// Interrupt flag: interrupt remapping fault.
    pub interrupt: bool,
}

impl PageFaultEvent {
    /// Encode into the four dwords of the event entry.
    #[must_use]
    pub const fn words(&self) -> [u32; 4] {
        let d0 = (self.device_id as u32)
            | ((self.guest_nested as u32) << 16)
            | ((self.nx as u32) << 17)
            | ((self.rz as u32) << 18)
            | ((self.translation as u32) << 19)
            | ((self.reserved as u32) << 20)
            | ((self.permission as u32) << 21)
            | ((self.write as u32) << 22)
            | ((self.interrupt as u32) << 23);
        let d1 = (EventCode::IO_PAGE_FAULT.0 as u32) << 28 | (self.domain_id & 0xf_ffff);
        let d2 = ((self.addr >> 12) as u32) & 0xf_ffff;
        let d3 = (self.addr >> 32) as u32;
        [d0, d1, d2, d3]
    }
}

/// One event log entry (parsed/typed view).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// IO_PAGE_FAULT.
    PageFault(PageFaultEvent),
    /// Any other event: keep the raw words and code.
    Raw {
        /// Event code.
        code: EventCode,
        /// Raw dwords.
        words: [u32; 4],
    },
}

impl Event {
    /// Event code.
    #[must_use]
    pub const fn code(&self) -> EventCode {
        match self {
            Event::PageFault(_) => EventCode::IO_PAGE_FAULT,
            Event::Raw { code, .. } => *code,
        }
    }

    /// Encode as four dwords.
    #[must_use]
    pub const fn words(&self) -> [u32; 4] {
        match self {
            Event::PageFault(f) => f.words(),
            Event::Raw { words, .. } => *words,
        }
    }

    /// Decode from raw dwords; unrecognized codes yield [`Event::Raw`].
    #[must_use]
    pub const fn from_words(words: [u32; 4]) -> Self {
        let code = EventCode::from_dword1(words[1]);
        match code {
            EventCode::IO_PAGE_FAULT => {
                let f = PageFaultEvent {
                    device_id: (words[0] & 0xffff) as u16,
                    domain_id: words[1] & 0xf_ffff,
                    addr: (((words[3] as u64) << 32)
                        | (((words[2] & 0xf_ffff) as u64) << 12)),
                    guest_nested: words[0] & (1 << 16) != 0,
                    nx: words[0] & (1 << 17) != 0,
                    rz: words[0] & (1 << 18) != 0,
                    translation: words[0] & (1 << 19) != 0,
                    reserved: words[0] & (1 << 20) != 0,
                    permission: words[0] & (1 << 21) != 0,
                    write: words[0] & (1 << 22) != 0,
                    interrupt: words[0] & (1 << 23) != 0,
                };
                Event::PageFault(f)
            }
            _ => Event::Raw { code, words },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_fault_roundtrip() {
        let e = Event::PageFault(PageFaultEvent {
            device_id: 0x0bad,
            domain_id: 0x12,
            addr: 0x1234_5678_9000,
            write: true,
            permission: true,
            ..PageFaultEvent::default()
        });
        let w = e.words();
        assert_eq!(EventCode::from_dword1(w[1]), EventCode::IO_PAGE_FAULT);
        match Event::from_words(w) {
            Event::PageFault(f) => {
                assert_eq!(f.device_id, 0x0bad);
                assert_eq!(f.domain_id, 0x12);
                assert_eq!(f.addr, 0x1234_5678_9000);
                assert!(f.write && f.permission);
                assert!(!f.nx);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
