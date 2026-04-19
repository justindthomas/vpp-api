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
