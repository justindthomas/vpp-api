//! VPP Linux-CP plugin API.
//!
//! Wire format validated against VPP 25.10 lcp.api.json. The plain
//! `lcp_itf_pair_add_del` message is used (v2 and v3 exist in newer
//! VPPs but share the same wire layout and CRC — this is the variant
//! marked as stable in 25.10).

use crate::error::VppError;
use crate::message::*;

/// Host interface kind for an LCP pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LcpItfHostType {
    Tap = 0,
    Tun = 1,
}

/// Add or delete a Linux Control Plane interface pair. Creates a
/// Linux-side TAP/TUN that mirrors a VPP sw_if_index — the backbone
/// of VPP-kernel control-plane integration (routing daemons bind
/// sockets in Linux, packets cross into VPP via the pair).
///
/// Wire layout (after 10-byte request header):
///   is_add: u8
///   sw_if_index: u32
///   host_if_name: [u8; 16]   (fixed NUL-padded)
///   host_if_type: u8         (0=TAP, 1=TUN)
///   netns: [u8; 32]          (fixed NUL-padded; empty = default ns)
#[derive(Debug, Clone)]
pub struct LcpItfPairAddDel {
    pub is_add: bool,
    pub sw_if_index: u32,
    pub host_if_name: String,
    pub host_if_type: LcpItfHostType,
    /// Network namespace name. Empty string = default netns. VPP
    /// treats non-absolute paths as netns *names* under /var/run/netns.
    pub netns: String,
}

impl LcpItfPairAddDel {
    /// Build an add-pair request with the common TAP + default-netns
    /// shape used by IMP (loopbacks and sub-interfaces cross-connected
    /// into Linux for the routing daemons).
    pub fn add_tap(sw_if_index: u32, host_if_name: impl Into<String>) -> Self {
        Self {
            is_add: true,
            sw_if_index,
            host_if_name: host_if_name.into(),
            host_if_type: LcpItfHostType::Tap,
            netns: String::new(),
        }
    }

    /// Shape for deleting a pair — only sw_if_index matters on del
    /// but we keep the full struct for wire-format consistency.
    pub fn del(sw_if_index: u32) -> Self {
        Self {
            is_add: false,
            sw_if_index,
            host_if_name: String::new(),
            host_if_type: LcpItfHostType::Tap,
            netns: String::new(),
        }
    }
}

impl VppMessage for LcpItfPairAddDel {
    const NAME: &'static str = "lcp_itf_pair_add_del";
    const CRC: &'static str = "40482b80";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.is_add as u8);
        put_u32(buf, self.sw_if_index);
        put_fixed_string(buf, &self.host_if_name, 16);
        put_u8(buf, self.host_if_type as u8);
        put_fixed_string(buf, &self.netns, 32);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("lcp_itf_pair_add_del is send-only".into()))
    }
}

#[derive(Debug, Clone)]
pub struct LcpItfPairAddDelReply {
    pub retval: i32,
}

impl VppMessage for LcpItfPairAddDelReply {
    const NAME: &'static str = "lcp_itf_pair_add_del_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(LcpItfPairAddDelReply { retval })
    }
}

fn put_fixed_string(buf: &mut Vec<u8>, s: &str, n: usize) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(n.saturating_sub(1));
    let mut pad = vec![0u8; n];
    pad[..len].copy_from_slice(&bytes[..len]);
    buf.extend_from_slice(&pad);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lcp_add_encode() {
        let msg = LcpItfPairAddDel::add_tap(5, "lo5");
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 1 (is_add) + 4 (sw_if_index) + 16 (host_if_name)
        //   + 1 (host_if_type) + 32 (netns) = 54
        assert_eq!(buf.len(), 54);
        assert_eq!(buf[0], 1); // is_add
        assert_eq!(&buf[1..5], &5u32.to_be_bytes());
        assert_eq!(&buf[5..8], b"lo5");
        assert!(buf[8..21].iter().all(|&b| b == 0));
        assert_eq!(buf[21], 0); // TAP
        assert!(buf[22..54].iter().all(|&b| b == 0)); // empty netns
    }

    #[test]
    fn test_lcp_del_encode() {
        let msg = LcpItfPairAddDel::del(9);
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        assert_eq!(buf.len(), 54);
        assert_eq!(buf[0], 0);
        assert_eq!(&buf[1..5], &9u32.to_be_bytes());
    }

    #[test]
    fn test_lcp_with_netns() {
        let msg = LcpItfPairAddDel {
            is_add: true,
            sw_if_index: 3,
            host_if_name: "eth-dp".to_string(),
            host_if_type: LcpItfHostType::Tap,
            netns: "dataplane".to_string(),
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        assert_eq!(&buf[5..11], b"eth-dp");
        assert_eq!(&buf[22..31], b"dataplane");
        assert!(buf[31..54].iter().all(|&b| b == 0));
    }
}
