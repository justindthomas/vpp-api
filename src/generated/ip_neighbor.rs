//! VPP IP neighbor (ARP/NDP) API messages.
//!
//! Wire format validated against VPP 25.10 ip_neighbor.api.json.

use crate::error::VppError;
use crate::message::*;

/// IP neighbor flags (u8 enum in VPP).
#[derive(Debug, Clone, Copy, Default)]
pub struct IpNeighborFlags(pub u8);

impl IpNeighborFlags {
    pub const NONE: u8 = 0;
    pub const STATIC: u8 = 1;
    pub const NO_FIB_ENTRY: u8 = 2;

    pub fn is_static(self) -> bool {
        self.0 & Self::STATIC != 0
    }
}

/// An IP neighbor entry.
///
/// Wire layout (ip_neighbor_t):
///   sw_if_index: u32 (interface_index alias)
///   flags: u8 (ip_neighbor_flags)
///   mac_address: [u8; 6] (mac_address alias)
///   ip_address: address_t = af(u8) + un(16 bytes) = 17 bytes
/// Total: 4 + 1 + 6 + 17 = 28 bytes
#[derive(Debug, Clone)]
pub struct IpNeighbor {
    pub sw_if_index: u32,
    pub flags: IpNeighborFlags,
    pub mac_address: [u8; 6],
    /// Address family: 0=IPv4, 1=IPv6 (u8).
    pub af: u8,
    /// Address bytes: 16 bytes (union — IPv4 uses first 4).
    pub ip_address: [u8; 16],
}

impl IpNeighbor {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
        put_u8(buf, self.flags.0);
        put_bytes(buf, &self.mac_address);
        // address_t: af(u8) + un(16 bytes)
        put_u8(buf, self.af);
        put_bytes(buf, &self.ip_address);
    }

    pub fn decode(buf: &[u8], off: &mut usize) -> Result<Self, VppError> {
        let sw_if_index = get_u32(buf, off)?;
        let flags = IpNeighborFlags(get_u8(buf, off)?);
        let mac_address = get_array::<6>(buf, off)?;
        let af = get_u8(buf, off)?;
        let ip_address = get_array::<16>(buf, off)?;
        Ok(IpNeighbor {
            sw_if_index,
            flags,
            mac_address,
            af,
            ip_address,
        })
    }
}

/// Dump IP neighbors for an interface.
///
/// Fields (after common header):
///   sw_if_index: u32 (default ~0 = all interfaces)
///   af: u8 (address_family)
#[derive(Debug, Clone)]
pub struct IpNeighborDump {
    pub sw_if_index: u32,
    /// Address family: 0 = IPv4, 1 = IPv6.
    pub af: u8,
}

impl VppMessage for IpNeighborDump {
    const NAME: &'static str = "ip_neighbor_dump";
    const CRC: &'static str = "d817a484";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
        put_u8(buf, self.af);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("ip_neighbor_dump is send-only".into()))
    }
}

/// Single neighbor entry returned by ip_neighbor_dump.
///
/// Fields (after common header):
///   age: f64
///   neighbor: ip_neighbor_t (28 bytes)
#[derive(Debug, Clone)]
pub struct IpNeighborDetails {
    pub age: f64,
    pub neighbor: IpNeighbor,
}

impl VppMessage for IpNeighborDetails {
    const NAME: &'static str = "ip_neighbor_details";
    const CRC: &'static str = "e29d79f0";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let age = f64::from_bits(get_u64(buf, &mut off)?);
        let neighbor = IpNeighbor::decode(buf, &mut off)?;
        Ok(IpNeighborDetails { age, neighbor })
    }
}
