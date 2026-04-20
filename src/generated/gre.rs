//! VPP GRE tunnel plugin API.
//!
//! Wire format validated against VPP 25.10 gre.api.json. Uses the
//! plain `gre_tunnel_add_del` (v1) — v2 adds per-tunnel TTL/DSCP
//! knobs which IMP doesn't use yet.

use crate::error::VppError;
use crate::generated::ip::AddressFamily;
use crate::message::*;

/// GRE tunnel type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GreTunnelType {
    /// L3 payload (the common case for IPv4/IPv6 over GRE).
    L3 = 0,
    /// Transparent Ethernet Bridging (GRE carries L2 frames).
    Teb = 1,
    /// ERSPAN (Ethernet mirroring over GRE).
    Erspan = 2,
}

/// Tunnel point-to-point vs. multipoint mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TunnelMode {
    P2p = 0,
    Mp = 1,
}

/// Nested `gre_tunnel` struct used by gre_tunnel_add_del.
///
/// Wire layout:
///   type: u8
///   mode: u8
///   flags: u8 (tunnel_encap_decap_flags_t — u8 enumflags, 0 = "none")
///   session_id: u16
///   instance: u32 (user-assigned index, ~0 = auto)
///   outer_table_id: u32 (VRF for outer packet; 0 = default)
///   sw_if_index: u32 (populated on reply; ignored on request)
///   src: vl_api_address_t (17 bytes)
///   dst: vl_api_address_t (17 bytes)
#[derive(Debug, Clone)]
pub struct GreTunnel {
    pub tunnel_type: GreTunnelType,
    pub mode: TunnelMode,
    pub flags: u8,
    pub session_id: u16,
    pub instance: u32,
    pub outer_table_id: u32,
    pub sw_if_index: u32,
    pub src_af: AddressFamily,
    pub src: [u8; 16],
    pub dst_af: AddressFamily,
    pub dst: [u8; 16],
}

impl GreTunnel {
    /// Common case: IPv4 L3 GRE, pinned instance number, default
    /// VRF, p2p mode, no flags.
    pub fn ipv4_l3(instance: u32, src: [u8; 4], dst: [u8; 4]) -> Self {
        let mut s16 = [0u8; 16];
        s16[..4].copy_from_slice(&src);
        let mut d16 = [0u8; 16];
        d16[..4].copy_from_slice(&dst);
        Self {
            tunnel_type: GreTunnelType::L3,
            mode: TunnelMode::P2p,
            flags: 0,
            session_id: 0,
            instance,
            outer_table_id: 0,
            sw_if_index: u32::MAX,
            src_af: AddressFamily::Ipv4,
            src: s16,
            dst_af: AddressFamily::Ipv4,
            dst: d16,
        }
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.tunnel_type as u8);
        put_u8(buf, self.mode as u8);
        put_u8(buf, self.flags);
        put_u16(buf, self.session_id);
        put_u32(buf, self.instance);
        put_u32(buf, self.outer_table_id);
        put_u32(buf, self.sw_if_index);
        put_u8(buf, self.src_af as u8);
        buf.extend_from_slice(&self.src);
        put_u8(buf, self.dst_af as u8);
        buf.extend_from_slice(&self.dst);
    }
}

/// Create or delete a GRE tunnel. On add the reply carries the
/// sw_if_index VPP allocated for the new interface; that index is
/// also deterministic as `gre{instance}` in vppctl's view.
///
/// Wire layout (after 10-byte request header):
///   is_add: u8
///   tunnel: gre_tunnel (54 bytes)
#[derive(Debug, Clone)]
pub struct GreTunnelAddDel {
    pub is_add: bool,
    pub tunnel: GreTunnel,
}

impl VppMessage for GreTunnelAddDel {
    const NAME: &'static str = "gre_tunnel_add_del";
    const CRC: &'static str = "a27d7f17";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.is_add as u8);
        self.tunnel.encode(buf);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("gre_tunnel_add_del is send-only".into()))
    }
}

/// Reply carries the allocated sw_if_index (same wire shape as
/// create_loopback_reply / create_vlan_subif_reply).
#[derive(Debug, Clone)]
pub struct GreTunnelAddDelReply {
    pub retval: i32,
    pub sw_if_index: u32,
}

impl VppMessage for GreTunnelAddDelReply {
    const NAME: &'static str = "gre_tunnel_add_del_reply";
    const CRC: &'static str = "5383d31f";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        let sw_if_index = get_u32(buf, &mut off)?;
        Ok(GreTunnelAddDelReply {
            retval,
            sw_if_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gre_tunnel_ipv4_encode() {
        let msg = GreTunnelAddDel {
            is_add: true,
            tunnel: GreTunnel::ipv4_l3(7, [192, 0, 2, 1], [203, 0, 113, 1]),
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 1 (is_add) + 1 (type) + 1 (mode) + 1 (flags) + 2 (session_id)
        //   + 4 (instance) + 4 (outer_table_id) + 4 (sw_if_index)
        //   + 17 (src_af + src[16]) + 17 (dst_af + dst[16]) = 52
        assert_eq!(buf.len(), 52);
        assert_eq!(buf[0], 1); // is_add
        assert_eq!(buf[1], 0); // L3
        assert_eq!(buf[2], 0); // P2P
        assert_eq!(buf[3], 0); // flags
        assert_eq!(&buf[4..6], &0u16.to_be_bytes()); // session_id
        assert_eq!(&buf[6..10], &7u32.to_be_bytes()); // instance
        assert_eq!(&buf[10..14], &0u32.to_be_bytes()); // outer_table_id
        assert_eq!(&buf[14..18], &u32::MAX.to_be_bytes()); // sw_if_index
        assert_eq!(buf[18], 0); // src af = v4
        assert_eq!(&buf[19..23], &[192, 0, 2, 1]);
        assert_eq!(buf[35], 0); // dst af = v4
        assert_eq!(&buf[36..40], &[203, 0, 113, 1]);
    }

    #[test]
    fn test_gre_reply_decode() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&9u32.to_be_bytes());
        let r = GreTunnelAddDelReply::decode_fields(&buf).unwrap();
        assert_eq!(r.retval, 0);
        assert_eq!(r.sw_if_index, 9);
    }
}
