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

/// Bridge-domain feature flags. u32 bitmask matching the
/// `bd_flags` enum in l2.api. Use with `BridgeFlags` below to
/// set/clear any subset on an existing BD.
#[derive(Debug, Clone, Copy, Default)]
pub struct BdFlags(pub u32);

impl BdFlags {
    pub const NONE: u32 = 0;
    pub const LEARN: u32 = 1;
    pub const FWD: u32 = 2;
    pub const FLOOD: u32 = 4;
    pub const UU_FLOOD: u32 = 8;
    pub const ARP_TERM: u32 = 16;
    pub const ARP_UFWD: u32 = 32;
}

/// Set or clear feature bits on an existing bridge domain. Use
/// `is_set=true` + a bitmask of BdFlags::* to turn features on, or
/// `is_set=false` + the same bitmask to turn them off.
///
/// Wire layout (after 10-byte request header):
///   bd_id: u32
///   is_set: u8
///   flags: u32
#[derive(Debug, Clone)]
pub struct BridgeFlags {
    pub bd_id: u32,
    pub is_set: bool,
    pub flags: BdFlags,
}

impl VppMessage for BridgeFlags {
    const NAME: &'static str = "bridge_flags";
    const CRC: &'static str = "1b0c5fbd";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.bd_id);
        put_u8(buf, self.is_set as u8);
        put_u32(buf, self.flags.0);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("bridge_flags is send-only".into()))
    }
}

#[derive(Debug, Clone)]
pub struct BridgeFlagsReply {
    pub retval: i32,
}

impl VppMessage for BridgeFlagsReply {
    const NAME: &'static str = "bridge_flags_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(BridgeFlagsReply { retval })
    }
}

/// Add or remove a static L2 FIB entry (a MAC binding inside a
/// bridge domain pointed at a specific sw_if_index). `static_mac`
/// pins the entry so learning/aging can't remove it; `bvi_mac`
/// marks the MAC as belonging to the BVI for ARP termination;
/// `filter_mac` turns the entry into a drop rule.
///
/// Wire layout (after 10-byte request header):
///   mac: [u8; 6]
///   bd_id: u32
///   sw_if_index: u32
///   is_add: u8
///   static_mac: u8
///   filter_mac: u8
///   bvi_mac: u8
#[derive(Debug, Clone)]
pub struct L2fibAddDel {
    pub mac: [u8; 6],
    pub bd_id: u32,
    pub sw_if_index: u32,
    pub is_add: bool,
    pub static_mac: bool,
    pub filter_mac: bool,
    pub bvi_mac: bool,
}

impl VppMessage for L2fibAddDel {
    const NAME: &'static str = "l2fib_add_del";
    const CRC: &'static str = "eddda487";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.mac);
        put_u32(buf, self.bd_id);
        put_u32(buf, self.sw_if_index);
        put_u8(buf, self.is_add as u8);
        put_u8(buf, self.static_mac as u8);
        put_u8(buf, self.filter_mac as u8);
        put_u8(buf, self.bvi_mac as u8);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("l2fib_add_del is send-only".into()))
    }
}

#[derive(Debug, Clone)]
pub struct L2fibAddDelReply {
    pub retval: i32,
}

impl VppMessage for L2fibAddDelReply {
    const NAME: &'static str = "l2fib_add_del_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(L2fibAddDelReply { retval })
    }
}

/// L2 VLAN tag rewrite operation. Matches VPP's `l2_vtr_op_t` enum
/// (not exported in the .api but stable in VPP source). Use with
/// `L2InterfaceVlanTagRewrite` to pop/push/translate VLAN tags on
/// a sub-interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum L2VtrOp {
    Disabled = 0,
    Push1 = 1,
    Push2 = 2,
    Pop1 = 3,
    Pop2 = 4,
    Translate1To1 = 5,
    Translate1To2 = 6,
    Translate2To1 = 7,
    Translate2To2 = 8,
}

/// Configure VLAN tag rewrite on an interface.
///
/// Wire layout (after 10-byte request header):
///   sw_if_index: u32
///   vtr_op: u32
///   push_dot1q: u32
///   tag1: u32
///   tag2: u32
#[derive(Debug, Clone)]
pub struct L2InterfaceVlanTagRewrite {
    pub sw_if_index: u32,
    pub vtr_op: L2VtrOp,
    /// Non-zero to use dot1q encapsulation on push; zero = dot1ad.
    pub push_dot1q: u32,
    pub tag1: u32,
    pub tag2: u32,
}

impl L2InterfaceVlanTagRewrite {
    /// Common case: pop one tag (used for VLAN passthrough).
    pub fn pop1(sw_if_index: u32) -> Self {
        Self {
            sw_if_index,
            vtr_op: L2VtrOp::Pop1,
            push_dot1q: 0,
            tag1: 0,
            tag2: 0,
        }
    }

    /// Disable VTR entirely.
    pub fn disable(sw_if_index: u32) -> Self {
        Self {
            sw_if_index,
            vtr_op: L2VtrOp::Disabled,
            push_dot1q: 0,
            tag1: 0,
            tag2: 0,
        }
    }
}

impl VppMessage for L2InterfaceVlanTagRewrite {
    const NAME: &'static str = "l2_interface_vlan_tag_rewrite";
    const CRC: &'static str = "62cc0bbc";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
        put_u32(buf, self.vtr_op as u32);
        put_u32(buf, self.push_dot1q);
        put_u32(buf, self.tag1);
        put_u32(buf, self.tag2);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode(
            "l2_interface_vlan_tag_rewrite is send-only".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct L2InterfaceVlanTagRewriteReply {
    pub retval: i32,
}

impl VppMessage for L2InterfaceVlanTagRewriteReply {
    const NAME: &'static str = "l2_interface_vlan_tag_rewrite_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(L2InterfaceVlanTagRewriteReply { retval })
    }
}

/// Wire an L2 cross-connect (rx→tx one-way forward). For a
/// bidirectional VLAN passthrough, send this twice with swapped
/// rx/tx interfaces.
///
/// Wire layout (after 10-byte request header):
///   rx_sw_if_index: u32
///   tx_sw_if_index: u32
///   enable: u8
#[derive(Debug, Clone)]
pub struct SwInterfaceSetL2Xconnect {
    pub rx_sw_if_index: u32,
    pub tx_sw_if_index: u32,
    pub enable: bool,
}

impl SwInterfaceSetL2Xconnect {
    pub fn enable(rx: u32, tx: u32) -> Self {
        Self {
            rx_sw_if_index: rx,
            tx_sw_if_index: tx,
            enable: true,
        }
    }

    pub fn disable(rx: u32) -> Self {
        Self {
            rx_sw_if_index: rx,
            tx_sw_if_index: 0,
            enable: false,
        }
    }
}

impl VppMessage for SwInterfaceSetL2Xconnect {
    const NAME: &'static str = "sw_interface_set_l2_xconnect";
    const CRC: &'static str = "4fa28a85";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.rx_sw_if_index);
        put_u32(buf, self.tx_sw_if_index);
        put_u8(buf, self.enable as u8);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode(
            "sw_interface_set_l2_xconnect is send-only".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct SwInterfaceSetL2XconnectReply {
    pub retval: i32,
}

impl VppMessage for SwInterfaceSetL2XconnectReply {
    const NAME: &'static str = "sw_interface_set_l2_xconnect_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(SwInterfaceSetL2XconnectReply { retval })
    }
}

/// Static IP↔MAC binding for a bridge domain's ARP-termination
/// table. Used on BVI bridges where you want the bridge itself
/// to answer ARP for a given IP rather than flooding the request.
///
/// Wire layout:
///   is_add: u8
///   entry.bd_id: u32
///   entry.ip: address_t (17 bytes: af + 16-byte union)
///   entry.mac: [u8; 6]
#[derive(Debug, Clone)]
pub struct BdIpMacAddDel {
    pub is_add: bool,
    pub bd_id: u32,
    /// 0=v4, 1=v6 — drives how the 16-byte ip field is interpreted.
    pub ip_af: crate::generated::ip::AddressFamily,
    pub ip: [u8; 16],
    pub mac: [u8; 6],
}

impl BdIpMacAddDel {
    pub fn ipv4(bd_id: u32, ip: [u8; 4], mac: [u8; 6], is_add: bool) -> Self {
        let mut ip16 = [0u8; 16];
        ip16[..4].copy_from_slice(&ip);
        Self {
            is_add,
            bd_id,
            ip_af: crate::generated::ip::AddressFamily::Ipv4,
            ip: ip16,
            mac,
        }
    }

    pub fn ipv6(bd_id: u32, ip: [u8; 16], mac: [u8; 6], is_add: bool) -> Self {
        Self {
            is_add,
            bd_id,
            ip_af: crate::generated::ip::AddressFamily::Ipv6,
            ip,
            mac,
        }
    }
}

impl VppMessage for BdIpMacAddDel {
    const NAME: &'static str = "bd_ip_mac_add_del";
    const CRC: &'static str = "0257c869";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.is_add as u8);
        put_u32(buf, self.bd_id);
        put_u8(buf, self.ip_af as u8);
        buf.extend_from_slice(&self.ip);
        buf.extend_from_slice(&self.mac);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("bd_ip_mac_add_del is send-only".into()))
    }
}

#[derive(Debug, Clone)]
pub struct BdIpMacAddDelReply {
    pub retval: i32,
}

impl VppMessage for BdIpMacAddDelReply {
    const NAME: &'static str = "bd_ip_mac_add_del_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(BdIpMacAddDelReply { retval })
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

    #[test]
    fn test_bridge_flags_encode() {
        let msg = BridgeFlags {
            bd_id: 100,
            is_set: false,
            flags: BdFlags(BdFlags::LEARN | BdFlags::FLOOD),
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 4 (bd_id) + 1 (is_set) + 4 (flags) = 9
        assert_eq!(buf.len(), 9);
        assert_eq!(&buf[0..4], &100u32.to_be_bytes());
        assert_eq!(buf[4], 0); // clear
        assert_eq!(&buf[5..9], &(1u32 | 4).to_be_bytes());
    }

    #[test]
    fn test_l2fib_add_del_encode() {
        let msg = L2fibAddDel {
            mac: [0x02, 0, 0, 0, 0, 0x01],
            bd_id: 10,
            sw_if_index: 3,
            is_add: true,
            static_mac: true,
            filter_mac: false,
            bvi_mac: true,
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 6 + 4 + 4 + 1 + 1 + 1 + 1 = 18
        assert_eq!(buf.len(), 18);
        assert_eq!(&buf[0..6], &[0x02, 0, 0, 0, 0, 0x01]);
        assert_eq!(&buf[6..10], &10u32.to_be_bytes());
        assert_eq!(&buf[10..14], &3u32.to_be_bytes());
        assert_eq!(buf[14], 1); // is_add
        assert_eq!(buf[15], 1); // static
        assert_eq!(buf[16], 0); // filter
        assert_eq!(buf[17], 1); // bvi
    }

    #[test]
    fn test_vlan_tag_rewrite_pop1_encode() {
        let msg = L2InterfaceVlanTagRewrite::pop1(5);
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 4 * 5 = 20
        assert_eq!(buf.len(), 20);
        assert_eq!(&buf[0..4], &5u32.to_be_bytes());
        assert_eq!(&buf[4..8], &3u32.to_be_bytes()); // Pop1
    }

    #[test]
    fn test_xconnect_encode() {
        let msg = SwInterfaceSetL2Xconnect::enable(3, 4);
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 4 + 4 + 1 = 9
        assert_eq!(buf.len(), 9);
        assert_eq!(&buf[0..4], &3u32.to_be_bytes());
        assert_eq!(&buf[4..8], &4u32.to_be_bytes());
        assert_eq!(buf[8], 1);
    }

    #[test]
    fn test_bd_ip_mac_encode() {
        let msg = BdIpMacAddDel::ipv4(7, [10, 0, 0, 1], [0x02, 0, 0, 0, 0, 0x09], true);
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 1 (is_add) + 4 (bd_id) + 1 (af) + 16 (ip) + 6 (mac) = 28
        assert_eq!(buf.len(), 28);
        assert_eq!(buf[0], 1);
        assert_eq!(&buf[1..5], &7u32.to_be_bytes());
        assert_eq!(buf[5], 0); // v4
        assert_eq!(&buf[6..10], &[10, 0, 0, 1]);
        assert_eq!(&buf[22..28], &[0x02, 0, 0, 0, 0, 0x09]);
    }
}
