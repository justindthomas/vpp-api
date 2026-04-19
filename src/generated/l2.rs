//! VPP L2 (bridge domain + L2 switching) API messages.
//!
//! Wire format validated against VPP 25.10 l2.api.json. Uses the v2
//! variant of bridge_domain_add_del — v1 is marked deprecated in 25.10.

use crate::error::VppError;
use crate::message::*;

/// L2 port type. Used when attaching a sw_if_index to a bridge domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum L2PortType {
    Normal = 0,
    Bvi = 1,
    UuFwd = 2,
}

/// Create or delete an L2 bridge domain (v2).
///
/// Use `bd_id = u32::MAX` to auto-allocate. The reply carries the
/// final (possibly-allocated) `bd_id`.
///
/// Wire layout (after 10-byte request header):
///   bd_id: u32
///   flood: u8
///   uu_flood: u8
///   forward: u8
///   learn: u8
///   arp_term: u8
///   arp_ufwd: u8
///   mac_age: u8
///   bd_tag: [u8; 64]  (fixed NUL-padded)
///   is_add: u8
#[derive(Debug, Clone)]
pub struct BridgeDomainAddDelV2 {
    pub bd_id: u32,
    pub flood: bool,
    pub uu_flood: bool,
    pub forward: bool,
    pub learn: bool,
    pub arp_term: bool,
    pub arp_ufwd: bool,
    pub mac_age: u8,
    pub bd_tag: String,
    pub is_add: bool,
}

impl BridgeDomainAddDelV2 {
    /// Create a bridge domain with the VPP-default flooding/forwarding
    /// flags (all on, arp_term off). Matches the behavior of VPP's
    /// `create bridge-domain <id>` CLI.
    pub fn add(bd_id: u32) -> Self {
        Self {
            bd_id,
            flood: true,
            uu_flood: true,
            forward: true,
            learn: true,
            arp_term: false,
            arp_ufwd: false,
            mac_age: 0,
            bd_tag: String::new(),
            is_add: true,
        }
    }

    pub fn del(bd_id: u32) -> Self {
        Self {
            bd_id,
            flood: false,
            uu_flood: false,
            forward: false,
            learn: false,
            arp_term: false,
            arp_ufwd: false,
            mac_age: 0,
            bd_tag: String::new(),
            is_add: false,
        }
    }
}

impl VppMessage for BridgeDomainAddDelV2 {
    const NAME: &'static str = "bridge_domain_add_del_v2";
    const CRC: &'static str = "600b7170";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.bd_id);
        put_u8(buf, self.flood as u8);
        put_u8(buf, self.uu_flood as u8);
        put_u8(buf, self.forward as u8);
        put_u8(buf, self.learn as u8);
        put_u8(buf, self.arp_term as u8);
        put_u8(buf, self.arp_ufwd as u8);
        put_u8(buf, self.mac_age);
        put_fixed_string(buf, &self.bd_tag, 64);
        put_u8(buf, self.is_add as u8);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode(
            "bridge_domain_add_del_v2 is send-only".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct BridgeDomainAddDelV2Reply {
    pub retval: i32,
    pub bd_id: u32,
}

impl VppMessage for BridgeDomainAddDelV2Reply {
    const NAME: &'static str = "bridge_domain_add_del_v2_reply";
    const CRC: &'static str = "fcb1e980";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        let bd_id = get_u32(buf, &mut off)?;
        Ok(BridgeDomainAddDelV2Reply { retval, bd_id })
    }
}

/// Attach a sw_if_index to a bridge domain (or detach back to L3).
///
/// Wire layout (after 10-byte request header):
///   rx_sw_if_index: u32
///   bd_id: u32
///   port_type: u32  (L2PortType)
///   shg: u8         (split horizon group; 0 for none)
///   enable: u8      (0 = back to L3 mode)
#[derive(Debug, Clone)]
pub struct SwInterfaceSetL2Bridge {
    pub rx_sw_if_index: u32,
    pub bd_id: u32,
    pub port_type: L2PortType,
    pub shg: u8,
    pub enable: bool,
}

impl SwInterfaceSetL2Bridge {
    /// Attach a member interface to a bridge domain as a normal L2 port.
    pub fn attach(rx_sw_if_index: u32, bd_id: u32) -> Self {
        Self {
            rx_sw_if_index,
            bd_id,
            port_type: L2PortType::Normal,
            shg: 0,
            enable: true,
        }
    }

    /// Attach an interface as the BVI (bridged-virtual interface) for
    /// an L3-routable bridge domain.
    pub fn attach_bvi(rx_sw_if_index: u32, bd_id: u32) -> Self {
        Self {
            rx_sw_if_index,
            bd_id,
            port_type: L2PortType::Bvi,
            shg: 0,
            enable: true,
        }
    }

    /// Detach an interface (put back into L3 mode).
    pub fn detach(rx_sw_if_index: u32) -> Self {
        Self {
            rx_sw_if_index,
            bd_id: 0,
            port_type: L2PortType::Normal,
            shg: 0,
            enable: false,
        }
    }
}

impl VppMessage for SwInterfaceSetL2Bridge {
    const NAME: &'static str = "sw_interface_set_l2_bridge";
    const CRC: &'static str = "d0678b13";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.rx_sw_if_index);
        put_u32(buf, self.bd_id);
        put_u32(buf, self.port_type as u32);
        put_u8(buf, self.shg);
        put_u8(buf, self.enable as u8);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode(
            "sw_interface_set_l2_bridge is send-only".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct SwInterfaceSetL2BridgeReply {
    pub retval: i32,
}

impl VppMessage for SwInterfaceSetL2BridgeReply {
    const NAME: &'static str = "sw_interface_set_l2_bridge_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(SwInterfaceSetL2BridgeReply { retval })
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
    fn test_bridge_domain_add_encode() {
        let msg = BridgeDomainAddDelV2::add(10);
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 4 (bd_id) + 7 (7 x u8 flags) + 64 (bd_tag) + 1 (is_add) = 76
        assert_eq!(buf.len(), 76);
        assert_eq!(&buf[0..4], &10u32.to_be_bytes());
        assert_eq!(buf[4], 1); // flood
        assert_eq!(buf[5], 1); // uu_flood
        assert_eq!(buf[6], 1); // forward
        assert_eq!(buf[7], 1); // learn
        assert_eq!(buf[8], 0); // arp_term
        assert_eq!(buf[9], 0); // arp_ufwd
        assert_eq!(buf[10], 0); // mac_age
        assert!(buf[11..75].iter().all(|&b| b == 0)); // bd_tag empty
        assert_eq!(buf[75], 1); // is_add
    }

    #[test]
    fn test_bridge_domain_reply_decode() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&42u32.to_be_bytes());
        let r = BridgeDomainAddDelV2Reply::decode_fields(&buf).unwrap();
        assert_eq!(r.retval, 0);
        assert_eq!(r.bd_id, 42);
    }

    #[test]
    fn test_set_l2_bridge_attach_encode() {
        let msg = SwInterfaceSetL2Bridge::attach(5, 10);
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        assert_eq!(buf.len(), 14);
        assert_eq!(&buf[0..4], &5u32.to_be_bytes());
        assert_eq!(&buf[4..8], &10u32.to_be_bytes());
        assert_eq!(&buf[8..12], &0u32.to_be_bytes()); // NORMAL
        assert_eq!(buf[12], 0); // shg
        assert_eq!(buf[13], 1); // enable
    }

    #[test]
    fn test_set_l2_bridge_bvi_encode() {
        let msg = SwInterfaceSetL2Bridge::attach_bvi(5, 10);
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        assert_eq!(&buf[8..12], &1u32.to_be_bytes()); // BVI
    }

    #[test]
    fn test_set_l2_bridge_detach_encode() {
        let msg = SwInterfaceSetL2Bridge::detach(5);
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        assert_eq!(buf[13], 0); // enable=false
    }
}
