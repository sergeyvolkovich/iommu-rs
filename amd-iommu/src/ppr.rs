//! Peripheral page request (PPR) log entries — section 2.6.
//!
//! PPR log entries are 128 bits with a 4-bit `PPRCode` at dword 1 bits
//! 31:28. The PAGE_SERVICE_REQUEST code (0001b) carries the device id,
//! PASID, request flags, tag and the faulting guest address.
//!
//! ```
//! use amd_iommu::ppr::{PprEntry, PprCode};
//!
//! let e = PprEntry {
//!     device_id: 0x1234,
//!     pasid: 0x5a,
//!     ppr_tag: 0x7,
//!     addr: 0x1234_5000,
//!     ..PprEntry::default()
//! };
//! let words = e.words();
//! assert_eq!((words[1] >> 28) & 0xf, PprCode::PAGE_SERVICE_REQUEST.0 as u32);
//! assert_eq!(words[0] & 0xffff, 0x1234);
//! assert_eq!(words[0] >> 16, 0x5a); // PASID[15:0]
//! ```

use crate::bits::extract_bits;

/// PPR log entry codes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PprCode(pub u8);

impl PprCode {
    /// PAGE_SERVICE_REQUEST (0001b).
    pub const PAGE_SERVICE_REQUEST: PprCode = PprCode(0x1);

    /// Extract from dword 1.
    #[must_use]
    pub const fn from_dword1(d: u32) -> Self {
        PprCode((d >> 28) as u8)
    }
}

/// A PAGE_SERVICE_REQUEST PPR log entry (figure 75).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PprEntry {
    /// DeviceID of the requester.
    pub device_id: u16,
    /// PASID of the request (20 bits; valid only when `gn` is clear).
    pub pasid: u32,
    /// PPR tag echoed by the COMPLETE_PPR_REQUEST command.
    pub ppr_tag: u16,
    /// Requested guest address.
    pub addr: u64,
    /// GN: guest nested — GPA request, PASID invalid.
    pub gn: bool,
    /// RZ: request with reserved bits set (needs recovery).
    pub rz: bool,
    /// US: user/supervisor requested.
    pub user: bool,
    /// WP: write permission requested.
    pub write: bool,
    /// RP: read permission requested.
    pub read: bool,
    /// NX: execute requested (0 = execute requested).
    pub nx: bool,
}

impl PprEntry {
    /// Encode into the four dwords of the log entry.
    #[must_use]
    pub const fn words(&self) -> [u32; 4] {
        let d0 = (self.device_id as u32) | ((self.pasid & 0xffff) << 16);
        let d1 = (PprCode::PAGE_SERVICE_REQUEST.0 as u32) << 28
            | ((self.gn as u32) << 26)
            | ((self.rz as u32) << 25)
            | ((self.user as u32) << 24)
            | ((self.write as u32) << 23)
            | ((self.read as u32) << 21)
            | ((self.nx as u32) << 20)
            | ((self.pasid >> 16) & 0xf) << 16
            | (self.ppr_tag as u32 & 0xffff);
        let d2 = ((self.addr >> 12) as u32) & 0xf_ffff;
        let d3 = (self.addr >> 32) as u32;
        [d0, d1, d2, d3]
    }

    /// Decode from raw dwords (PAGE_SERVICE_REQUEST format).
    #[must_use]
    pub const fn from_words(words: [u32; 4]) -> Self {
        PprEntry {
            device_id: (words[0] & 0xffff) as u16,
            pasid: (words[0] >> 16) | (extract_bits(words[1] as u64, 18, 16) as u32) << 16,
            ppr_tag: (words[1] & 0xffff) as u16,
            addr: ((words[3] as u64) << 32) | (((words[2] & 0xf_ffff) as u64) << 12),
            gn: words[1] & (1 << 26) != 0,
            rz: words[1] & (1 << 25) != 0,
            user: words[1] & (1 << 24) != 0,
            write: words[1] & (1 << 23) != 0,
            read: words[1] & (1 << 21) != 0,
            nx: words[1] & (1 << 20) != 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ppr_roundtrip() {
        let e = PprEntry {
            device_id: 0x0bad,
            pasid: 0x5_a5a5 & 0xf_ffff,
            ppr_tag: 0x1f,
            addr: 0x0000_1234_5000,
            write: true,
            ..PprEntry::default()
        };
        let w = e.words();
        match PprCode::from_dword1(w[1]) {
            PprCode::PAGE_SERVICE_REQUEST => {}
            other => panic!("bad code {other:?}"),
        }
        let back = PprEntry::from_words(w);
        assert_eq!(back.device_id, 0x0bad);
        assert_eq!(back.pasid, e.pasid);
        assert_eq!(back.ppr_tag, 0x1f);
        assert_eq!(back.addr, 0x1234_5000);
        assert!(back.write);
        assert!(!back.read);
    }
}
