//! VPP interface API messages.
//!
//! Wire format validated against VPP 25.10 interface.api.json.

use crate::error::VppError;
use crate::message::*;

/// Dump all interfaces.
#[derive(Debug, Clone)]
pub struct SwInterfaceDump {
    /// Filter by sw_if_index (~0 = all).
    pub sw_if_index: u32,
    /// Whether name_filter is valid.
    pub name_filter_valid: bool,
    /// Filter by name prefix.
    pub name_filter: String,
}

impl Default for SwInterfaceDump {
    fn default() -> Self {
        Self {
            sw_if_index: u32::MAX,
            name_filter_valid: false,
            name_filter: String::new(),
        }
    }
}

impl VppMessage for SwInterfaceDump {
    const NAME: &'static str = "sw_interface_dump";
    const CRC: &'static str = "aa610c27";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
        put_u8(buf, self.name_filter_valid as u8);
        // name_filter: string[49] — 4-byte length prefix + data
        let name_bytes = self.name_filter.as_bytes();
        let len = name_bytes.len().min(48);
        put_u32(buf, len as u32);
        buf.extend_from_slice(&name_bytes[..len]);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("sw_interface_dump is send-only".into()))
    }
}

/// Interface flags (admin up, link up). u32 enum.
#[derive(Debug, Clone, Copy, Default)]
pub struct IfStatusFlags(pub u32);

impl IfStatusFlags {
    pub const ADMIN_UP: u32 = 1;
    pub const LINK_UP: u32 = 2;

    pub fn is_admin_up(self) -> bool {
        self.0 & Self::ADMIN_UP != 0
    }

    pub fn is_link_up(self) -> bool {
        self.0 & Self::LINK_UP != 0
    }
}

/// Details for a single interface (reply to SwInterfaceDump).
///
/// Wire layout (after 6-byte reply header):
///   sw_if_index: u32 (interface_index alias)
///   sup_sw_if_index: u32
///   l2_address: [u8; 6] (mac_address alias)
///   flags: u32 (if_status_flags)
///   type: u32 (if_type)
///   link_duplex: u32
///   link_speed: u32
///   link_mtu: u16
///   mtu: [u32; 4]
///   sub_id: u32
///   sub_number_of_tags: u8
///   sub_outer_vlan_id: u16
///   sub_inner_vlan_id: u16
///   sub_if_flags: u32
///   vtr_op: u32
///   vtr_push_dot1q: u32
///   vtr_tag1: u32
///   vtr_tag2: u32
///   outer_tag: u16
///   b_dmac: [u8; 6]
///   b_smac: [u8; 6]
///   b_vlanid: u16
///   i_sid: u32
///   interface_name: [u8; 64] (NUL-padded)
///   interface_dev_type: [u8; 64] (NUL-padded)
///   tag: [u8; 64] (NUL-padded)
/// Total fields: 97 + 192 = 289 bytes
#[derive(Debug, Clone)]
pub struct SwInterfaceDetails {
    pub sw_if_index: u32,
    pub sup_sw_if_index: u32,
    pub l2_address: [u8; 6],
    pub flags: IfStatusFlags,
    pub if_type: u32,
    pub link_duplex: u32,
    pub link_speed: u32,
    pub link_mtu: u16,
    pub mtu: [u32; 4],
    pub sub_id: u32,
    pub sub_number_of_tags: u8,
    pub sub_outer_vlan_id: u16,
    pub sub_inner_vlan_id: u16,
    pub sub_if_flags: u32,
    pub vtr_op: u32,
    pub vtr_push_dot1q: u32,
    pub vtr_tag1: u32,
    pub vtr_tag2: u32,
    pub outer_tag: u16,
    pub b_dmac: [u8; 6],
    pub b_smac: [u8; 6],
    pub b_vlanid: u16,
    pub i_sid: u32,
    pub interface_name: String,
    pub interface_dev_type: String,
    pub tag: String,
}

impl VppMessage for SwInterfaceDetails {
    const NAME: &'static str = "sw_interface_details";
    const CRC: &'static str = "6c221fc7";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {
        // We only receive this
    }

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;

        let sw_if_index = get_u32(buf, &mut off)?;
        let sup_sw_if_index = get_u32(buf, &mut off)?;
        let l2_address = get_array::<6>(buf, &mut off)?;
        let flags = IfStatusFlags(get_u32(buf, &mut off)?);
        let if_type = get_u32(buf, &mut off)?;
        let link_duplex = get_u32(buf, &mut off)?;
        let link_speed = get_u32(buf, &mut off)?;
        let link_mtu = get_u16(buf, &mut off)?;

        let mut mtu = [0u32; 4];
        for m in &mut mtu {
            *m = get_u32(buf, &mut off)?;
        }

        let sub_id = get_u32(buf, &mut off)?;
        let sub_number_of_tags = get_u8(buf, &mut off)?;
        let sub_outer_vlan_id = get_u16(buf, &mut off)?;
        let sub_inner_vlan_id = get_u16(buf, &mut off)?;
        let sub_if_flags = get_u32(buf, &mut off)?;
        let vtr_op = get_u32(buf, &mut off)?;
        let vtr_push_dot1q = get_u32(buf, &mut off)?;
        let vtr_tag1 = get_u32(buf, &mut off)?;
        let vtr_tag2 = get_u32(buf, &mut off)?;
        let outer_tag = get_u16(buf, &mut off)?;
        let b_dmac = get_array::<6>(buf, &mut off)?;
        let b_smac = get_array::<6>(buf, &mut off)?;
        let b_vlanid = get_u16(buf, &mut off)?;
        let i_sid = get_u32(buf, &mut off)?;

        // Three fixed-size 64-byte NUL-padded string fields
        let interface_name = get_string(buf, &mut off, 64)?;
        let interface_dev_type = get_string(buf, &mut off, 64)?;
        let tag = get_string(buf, &mut off, 64)?;

        Ok(SwInterfaceDetails {
            sw_if_index,
            sup_sw_if_index,
            l2_address,
            flags,
            if_type,
            link_duplex,
            link_speed,
            link_mtu,
            mtu,
            sub_id,
            sub_number_of_tags,
            sub_outer_vlan_id,
            sub_inner_vlan_id,
            sub_if_flags,
            vtr_op,
            vtr_push_dot1q,
            vtr_tag1,
            vtr_tag2,
            outer_tag,
            b_dmac,
            b_smac,
            b_vlanid,
            i_sid,
            interface_name,
            interface_dev_type,
            tag,
        })
    }
}

/// Register to receive interface events.
#[derive(Debug, Clone)]
pub struct WantInterfaceEvents {
    /// 1 = enable, 0 = disable.
    pub enable_disable: u32,
    /// Client PID.
    pub pid: u32,
}

impl VppMessage for WantInterfaceEvents {
    const NAME: &'static str = "want_interface_events";
    const CRC: &'static str = "476f5a08";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.enable_disable);
        put_u32(buf, self.pid);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("want_interface_events is send-only".into()))
    }
}

/// Reply to want_interface_events.
#[derive(Debug, Clone)]
pub struct WantInterfaceEventsReply {
    pub retval: i32,
}

impl VppMessage for WantInterfaceEventsReply {
    const NAME: &'static str = "want_interface_events_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(WantInterfaceEventsReply { retval })
    }
}

/// Asynchronous interface state change event.
///
/// Reply header: msg_id(2) + context(4) = 6 bytes, then:
///   pid: u32
///   sw_if_index: u32
///   flags: u32
///   deleted: bool(u8)
#[derive(Debug, Clone)]
pub struct SwInterfaceEvent {
    pub pid: u32,
    pub sw_if_index: u32,
    pub flags: IfStatusFlags,
    pub deleted: bool,
}

impl VppMessage for SwInterfaceEvent {
    const NAME: &'static str = "sw_interface_event";
    const CRC: &'static str = "2d3d95a7";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let pid = get_u32(buf, &mut off)?;
        let sw_if_index = get_u32(buf, &mut off)?;
        let flags = IfStatusFlags(get_u32(buf, &mut off)?);
        let deleted = get_u8(buf, &mut off)? != 0;
        Ok(SwInterfaceEvent {
            pid,
            sw_if_index,
            flags,
            deleted,
        })
    }
}

/// Set interface admin flags (up/down).
#[derive(Debug, Clone)]
pub struct SwInterfaceSetFlags {
    pub sw_if_index: u32,
    pub flags: IfStatusFlags,
}

impl VppMessage for SwInterfaceSetFlags {
    const NAME: &'static str = "sw_interface_set_flags";
    const CRC: &'static str = "f5aec1b8";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
        put_u32(buf, self.flags.0);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("sw_interface_set_flags is send-only".into()))
    }
}

/// Reply to sw_interface_set_flags.
#[derive(Debug, Clone)]
pub struct SwInterfaceSetFlagsReply {
    pub retval: i32,
}

impl VppMessage for SwInterfaceSetFlagsReply {
    const NAME: &'static str = "sw_interface_set_flags_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(SwInterfaceSetFlagsReply { retval })
    }
}

/// Add or remove an IPv4/IPv6 address on an interface.
///
/// Wire layout (after 10-byte request header):
///   sw_if_index: u32 (interface_index alias)
///   is_add: bool (u8)
///   del_all: bool (u8)
///   prefix: address_with_prefix_t = af(u8) + address(16) + len(u8) = 18 bytes
#[derive(Debug, Clone)]
pub struct SwInterfaceAddDelAddress {
    pub sw_if_index: u32,
    pub is_add: bool,
    pub del_all: bool,
    pub prefix: crate::generated::ip::Prefix,
}

impl VppMessage for SwInterfaceAddDelAddress {
    const NAME: &'static str = "sw_interface_add_del_address";
    const CRC: &'static str = "5463d73b";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
        put_u8(buf, self.is_add as u8);
        put_u8(buf, self.del_all as u8);
        self.prefix.encode(buf);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("sw_interface_add_del_address is send-only".into()))
    }
}

/// Reply to sw_interface_add_del_address.
#[derive(Debug, Clone)]
pub struct SwInterfaceAddDelAddressReply {
    pub retval: i32,
}

impl VppMessage for SwInterfaceAddDelAddressReply {
    const NAME: &'static str = "sw_interface_add_del_address_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(SwInterfaceAddDelAddressReply { retval })
    }
}

/// Set an interface's MTU. The `mtu` field is a 4-element array
/// indexed by vnet_mtu_t: [L3, IP4, IP6, MPLS]. Set all four to the
/// same value to behave like the `set interface mtu packet N <if>` CLI;
/// or set individual slots to tune per-proto MTU.
///
/// Wire layout (after 10-byte request header):
///   sw_if_index: u32
///   mtu: [u32; 4]
#[derive(Debug, Clone)]
pub struct SwInterfaceSetMtu {
    pub sw_if_index: u32,
    pub mtu: [u32; 4],
}

impl SwInterfaceSetMtu {
    /// Convenience: set all four MTU slots to the same value (matches
    /// VPP's `set interface mtu packet N <if>` CLI).
    pub fn packet(sw_if_index: u32, mtu: u32) -> Self {
        Self {
            sw_if_index,
            mtu: [mtu; 4],
        }
    }
}

impl VppMessage for SwInterfaceSetMtu {
    const NAME: &'static str = "sw_interface_set_mtu";
    const CRC: &'static str = "5cbe85e5";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
        for m in &self.mtu {
            put_u32(buf, *m);
        }
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("sw_interface_set_mtu is send-only".into()))
    }
}

/// Reply to sw_interface_set_mtu.
#[derive(Debug, Clone)]
pub struct SwInterfaceSetMtuReply {
    pub retval: i32,
}

impl VppMessage for SwInterfaceSetMtuReply {
    const NAME: &'static str = "sw_interface_set_mtu_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(SwInterfaceSetMtuReply { retval })
    }
}

/// Create a loopback interface.
///
/// `mac_address` all-zero = VPP picks a MAC.
#[derive(Debug, Clone, Default)]
pub struct CreateLoopback {
    pub mac_address: [u8; 6],
}

impl VppMessage for CreateLoopback {
    const NAME: &'static str = "create_loopback";
    const CRC: &'static str = "42bb5d22";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_bytes(buf, &self.mac_address);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("create_loopback is send-only".into()))
    }
}

/// Create a loopback interface with an explicit instance number
/// (controls the `loopN` name that shows up in VPP).
#[derive(Debug, Clone)]
pub struct CreateLoopbackInstance {
    pub mac_address: [u8; 6],
    /// If false VPP picks the instance (user_instance ignored).
    pub is_specified: bool,
    pub user_instance: u32,
}

impl CreateLoopbackInstance {
    pub fn instance(n: u32) -> Self {
        Self {
            mac_address: [0; 6],
            is_specified: true,
            user_instance: n,
        }
    }
}

impl VppMessage for CreateLoopbackInstance {
    const NAME: &'static str = "create_loopback_instance";
    const CRC: &'static str = "d36a3ee2";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_bytes(buf, &self.mac_address);
        put_u8(buf, self.is_specified as u8);
        put_u32(buf, self.user_instance);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode(
            "create_loopback_instance is send-only".into(),
        ))
    }
}

/// Reply carrying the newly-allocated sw_if_index. Used by both
/// `create_loopback_reply` and `create_loopback_instance_reply`
/// (identical wire format, distinct message names).
#[derive(Debug, Clone)]
pub struct CreateLoopbackReply {
    pub retval: i32,
    pub sw_if_index: u32,
}

impl VppMessage for CreateLoopbackReply {
    const NAME: &'static str = "create_loopback_reply";
    const CRC: &'static str = "5383d31f";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        let sw_if_index = get_u32(buf, &mut off)?;
        Ok(CreateLoopbackReply {
            retval,
            sw_if_index,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CreateLoopbackInstanceReply {
    pub retval: i32,
    pub sw_if_index: u32,
}

impl VppMessage for CreateLoopbackInstanceReply {
    const NAME: &'static str = "create_loopback_instance_reply";
    const CRC: &'static str = "5383d31f";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        let sw_if_index = get_u32(buf, &mut off)?;
        Ok(CreateLoopbackInstanceReply {
            retval,
            sw_if_index,
        })
    }
}

/// Delete a loopback interface.
#[derive(Debug, Clone)]
pub struct DeleteLoopback {
    pub sw_if_index: u32,
}

impl VppMessage for DeleteLoopback {
    const NAME: &'static str = "delete_loopback";
    const CRC: &'static str = "f9e6675e";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("delete_loopback is send-only".into()))
    }
}

#[derive(Debug, Clone)]
pub struct DeleteLoopbackReply {
    pub retval: i32,
}

impl VppMessage for DeleteLoopbackReply {
    const NAME: &'static str = "delete_loopback_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(DeleteLoopbackReply { retval })
    }
}

/// sub-interface flags bitfield. Encoded as u32 on the wire.
#[derive(Debug, Clone, Copy, Default)]
pub struct SubIfFlags(pub u32);

impl SubIfFlags {
    pub const NO_TAGS: u32 = 1;
    pub const ONE_TAG: u32 = 2;
    pub const TWO_TAGS: u32 = 4;
    pub const DOT1AD: u32 = 8;
    pub const EXACT_MATCH: u32 = 16;
    pub const DEFAULT: u32 = 32;
    pub const OUTER_VLAN_ID_ANY: u32 = 64;
    pub const INNER_VLAN_ID_ANY: u32 = 128;
}

/// Create a trivial 802.1Q sub-interface (one tag, exact match on
/// vlan_id). For QinQ / dot1ad, use `create_subif` instead.
#[derive(Debug, Clone)]
pub struct CreateVlanSubif {
    pub sw_if_index: u32,
    pub vlan_id: u32,
}

impl VppMessage for CreateVlanSubif {
    const NAME: &'static str = "create_vlan_subif";
    const CRC: &'static str = "af34ac8b";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
        put_u32(buf, self.vlan_id);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("create_vlan_subif is send-only".into()))
    }
}

#[derive(Debug, Clone)]
pub struct CreateVlanSubifReply {
    pub retval: i32,
    pub sw_if_index: u32,
}

impl VppMessage for CreateVlanSubifReply {
    const NAME: &'static str = "create_vlan_subif_reply";
    const CRC: &'static str = "5383d31f";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        let sw_if_index = get_u32(buf, &mut off)?;
        Ok(CreateVlanSubifReply {
            retval,
            sw_if_index,
        })
    }
}

/// General-purpose sub-interface create. Supports QinQ (two-tag) and
/// dot1ad via `sub_if_flags`.
#[derive(Debug, Clone)]
pub struct CreateSubif {
    pub sw_if_index: u32,
    pub sub_id: u32,
    pub sub_if_flags: SubIfFlags,
    pub outer_vlan_id: u16,
    pub inner_vlan_id: u16,
}

impl VppMessage for CreateSubif {
    const NAME: &'static str = "create_subif";
    const CRC: &'static str = "790ca755";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
        put_u32(buf, self.sub_id);
        put_u32(buf, self.sub_if_flags.0);
        put_u16(buf, self.outer_vlan_id);
        put_u16(buf, self.inner_vlan_id);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("create_subif is send-only".into()))
    }
}

#[derive(Debug, Clone)]
pub struct CreateSubifReply {
    pub retval: i32,
    pub sw_if_index: u32,
}

impl VppMessage for CreateSubifReply {
    const NAME: &'static str = "create_subif_reply";
    const CRC: &'static str = "5383d31f";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        let sw_if_index = get_u32(buf, &mut off)?;
        Ok(CreateSubifReply {
            retval,
            sw_if_index,
        })
    }
}

/// Delete a sub-interface. Also usable to delete a loopback (same
/// wire shape, different message name) — use `DeleteLoopback`
/// instead for clarity.
#[derive(Debug, Clone)]
pub struct DeleteSubif {
    pub sw_if_index: u32,
}

impl VppMessage for DeleteSubif {
    const NAME: &'static str = "delete_subif";
    const CRC: &'static str = "f9e6675e";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("delete_subif is send-only".into()))
    }
}

#[derive(Debug, Clone)]
pub struct DeleteSubifReply {
    pub retval: i32,
}

impl VppMessage for DeleteSubifReply {
    const NAME: &'static str = "delete_subif_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(DeleteSubifReply { retval })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::ip::Prefix;

    #[test]
    fn test_add_del_address_encode_ipv4() {
        let msg = SwInterfaceAddDelAddress {
            sw_if_index: 3,
            is_add: true,
            del_all: false,
            prefix: Prefix::ipv4([192, 168, 1, 1], 24),
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 4 (sw_if_index) + 1 (is_add) + 1 (del_all) + 18 (prefix) = 24
        assert_eq!(buf.len(), 24);
        assert_eq!(&buf[0..4], &3u32.to_be_bytes());
        assert_eq!(buf[4], 1); // is_add
        assert_eq!(buf[5], 0); // del_all
        assert_eq!(buf[6], 0); // af = v4
        assert_eq!(&buf[7..11], &[192, 168, 1, 1]);
        assert_eq!(buf[23], 24); // len
    }

    #[test]
    fn test_add_del_address_encode_ipv6() {
        let addr = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let msg = SwInterfaceAddDelAddress {
            sw_if_index: 5,
            is_add: false,
            del_all: false,
            prefix: Prefix::ipv6(addr, 64),
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        assert_eq!(buf.len(), 24);
        assert_eq!(buf[4], 0); // is_add=false
        assert_eq!(buf[6], 1); // af = v6
        assert_eq!(&buf[7..23], &addr);
        assert_eq!(buf[23], 64);
    }

    #[test]
    fn test_set_mtu_encode() {
        let msg = SwInterfaceSetMtu::packet(7, 9000);
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 4 (sw_if_index) + 4*4 (mtu array) = 20
        assert_eq!(buf.len(), 20);
        assert_eq!(&buf[0..4], &7u32.to_be_bytes());
        for slot in 0..4 {
            assert_eq!(
                &buf[4 + slot * 4..4 + (slot + 1) * 4],
                &9000u32.to_be_bytes()
            );
        }
    }

    #[test]
    fn test_reply_decode() {
        let buf = 0i32.to_be_bytes();
        let r = SwInterfaceAddDelAddressReply::decode_fields(&buf).unwrap();
        assert_eq!(r.retval, 0);
        let buf = (-13i32).to_be_bytes();
        let r = SwInterfaceSetMtuReply::decode_fields(&buf).unwrap();
        assert_eq!(r.retval, -13);
    }

    #[test]
    fn test_create_loopback_encode() {
        let msg = CreateLoopback {
            mac_address: [0x02, 0, 0, 0, 0, 0x01],
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        assert_eq!(buf, vec![0x02, 0, 0, 0, 0, 0x01]);
    }

    #[test]
    fn test_create_loopback_instance_encode() {
        let msg = CreateLoopbackInstance::instance(42);
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 6 (mac) + 1 (is_specified) + 4 (user_instance) = 11
        assert_eq!(buf.len(), 11);
        assert_eq!(&buf[0..6], &[0u8; 6]);
        assert_eq!(buf[6], 1);
        assert_eq!(&buf[7..11], &42u32.to_be_bytes());
    }

    #[test]
    fn test_create_loopback_reply_decode() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&7u32.to_be_bytes());
        let r = CreateLoopbackReply::decode_fields(&buf).unwrap();
        assert_eq!(r.retval, 0);
        assert_eq!(r.sw_if_index, 7);
    }

    #[test]
    fn test_create_vlan_subif_encode() {
        let msg = CreateVlanSubif {
            sw_if_index: 3,
            vlan_id: 100,
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        assert_eq!(buf.len(), 8);
        assert_eq!(&buf[0..4], &3u32.to_be_bytes());
        assert_eq!(&buf[4..8], &100u32.to_be_bytes());
    }

    #[test]
    fn test_create_subif_encode_qinq() {
        let msg = CreateSubif {
            sw_if_index: 5,
            sub_id: 100,
            sub_if_flags: SubIfFlags(SubIfFlags::TWO_TAGS | SubIfFlags::EXACT_MATCH),
            outer_vlan_id: 100,
            inner_vlan_id: 200,
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 4 + 4 + 4 + 2 + 2 = 16
        assert_eq!(buf.len(), 16);
        assert_eq!(&buf[0..4], &5u32.to_be_bytes());
        assert_eq!(&buf[4..8], &100u32.to_be_bytes());
        assert_eq!(&buf[8..12], &(4u32 | 16).to_be_bytes());
        assert_eq!(&buf[12..14], &100u16.to_be_bytes());
        assert_eq!(&buf[14..16], &200u16.to_be_bytes());
    }

    #[test]
    fn test_delete_subif_encode() {
        let msg = DeleteSubif { sw_if_index: 9 };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        assert_eq!(buf, 9u32.to_be_bytes());
    }
}
