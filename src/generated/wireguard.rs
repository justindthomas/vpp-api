//! VPP wireguard plugin API.
//!
//! Wire format validated against the Ecliptic patched VPP 25.10
//! wireguard.api.json (CRCs extracted from the live-build chroot's
//! /usr/share/vpp/api/plugins/wireguard.api.json — identical to
//! stock 25.10 for these messages, but sourced from our build so a
//! future patch that touches wireguard shows up as a CRC mismatch
//! at connect time instead of silent wire corruption).
//!
//! Peer status flags (wireguard_peer_flags, u8 enumflag):
//!   1 = WIREGUARD_PEER_STATUS_DEAD
//!   2 = WIREGUARD_PEER_ESTABLISHED

use crate::error::VppError;
use crate::generated::ip::AddressFamily;
use crate::message::*;

pub const WIREGUARD_PEER_STATUS_DEAD: u8 = 1;
pub const WIREGUARD_PEER_ESTABLISHED: u8 = 2;

fn decode_af(v: u8) -> AddressFamily {
    if v == 1 {
        AddressFamily::Ipv6
    } else {
        AddressFamily::Ipv4
    }
}

/// Nested `wireguard_interface` struct.
///
/// Wire layout (91 bytes):
///   user_instance: u32 (~0 = auto; wgN takes N from this)
///   sw_if_index: u32 (populated on details; ignored on create)
///   private_key: u8[32]
///   public_key: u8[32] (populated on details; ignored on create)
///   port: u16 (UDP listen port)
///   src_ip: vl_api_address_t (17 bytes — underlay source address)
#[derive(Debug, Clone)]
pub struct WireguardInterface {
    pub user_instance: u32,
    pub sw_if_index: u32,
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub port: u16,
    pub src_af: AddressFamily,
    pub src_ip: [u8; 16],
}

impl WireguardInterface {
    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.user_instance);
        put_u32(buf, self.sw_if_index);
        put_bytes(buf, &self.private_key);
        put_bytes(buf, &self.public_key);
        put_u16(buf, self.port);
        put_u8(buf, self.src_af as u8);
        put_bytes(buf, &self.src_ip);
    }

    pub(crate) fn decode(buf: &[u8], off: &mut usize) -> Result<Self, VppError> {
        let user_instance = get_u32(buf, off)?;
        let sw_if_index = get_u32(buf, off)?;
        let private_key: [u8; 32] = get_array(buf, off)?;
        let public_key: [u8; 32] = get_array(buf, off)?;
        let port = get_u16(buf, off)?;
        let src_af = decode_af(get_u8(buf, off)?);
        let src_ip: [u8; 16] = get_array(buf, off)?;
        Ok(Self {
            user_instance,
            sw_if_index,
            private_key,
            public_key,
            port,
            src_af,
            src_ip,
        })
    }
}

/// One allowed-ip prefix on a peer (vl_api_prefix_t, 18 bytes:
/// address_t(17) + len u8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireguardAllowedIp {
    pub af: AddressFamily,
    pub address: [u8; 16],
    pub len: u8,
}

impl WireguardAllowedIp {
    pub fn ipv4(addr: [u8; 4], len: u8) -> Self {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&addr);
        Self {
            af: AddressFamily::Ipv4,
            address: a,
            len,
        }
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.af as u8);
        put_bytes(buf, &self.address);
        put_u8(buf, self.len);
    }

    fn decode(buf: &[u8], off: &mut usize) -> Result<Self, VppError> {
        let af = decode_af(get_u8(buf, off)?);
        let address: [u8; 16] = get_array(buf, off)?;
        let len = get_u8(buf, off)?;
        Ok(Self { af, address, len })
    }
}

/// Nested `wireguard_peer` struct.
///
/// Wire layout (67 bytes + 18 per allowed-ip):
///   peer_index: u32 (populated on details; ignored on add)
///   public_key: u8[32]
///   port: u16 (peer UDP port — the `dst-port` in vppctl)
///   persistent_keepalive: u16 (seconds, 0 = off)
///   table_id: u32 (FIB table for endpoint lookup)
///   endpoint: vl_api_address_t (17)
///   sw_if_index: u32 (owning wg interface)
///   flags: u8 (status on details; 0 on add)
///   n_allowed_ips: u8
///   allowed_ips: n × vl_api_prefix_t (18 each)
#[derive(Debug, Clone)]
pub struct WireguardPeer {
    pub peer_index: u32,
    pub public_key: [u8; 32],
    pub port: u16,
    pub persistent_keepalive: u16,
    pub table_id: u32,
    pub endpoint_af: AddressFamily,
    pub endpoint: [u8; 16],
    pub sw_if_index: u32,
    pub flags: u8,
    pub allowed_ips: Vec<WireguardAllowedIp>,
}

impl WireguardPeer {
    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.peer_index);
        put_bytes(buf, &self.public_key);
        put_u16(buf, self.port);
        put_u16(buf, self.persistent_keepalive);
        put_u32(buf, self.table_id);
        put_u8(buf, self.endpoint_af as u8);
        put_bytes(buf, &self.endpoint);
        put_u32(buf, self.sw_if_index);
        put_u8(buf, self.flags);
        put_u8(buf, self.allowed_ips.len() as u8);
        for ip in &self.allowed_ips {
            ip.encode(buf);
        }
    }

    pub(crate) fn decode(buf: &[u8], off: &mut usize) -> Result<Self, VppError> {
        let peer_index = get_u32(buf, off)?;
        let public_key: [u8; 32] = get_array(buf, off)?;
        let port = get_u16(buf, off)?;
        let persistent_keepalive = get_u16(buf, off)?;
        let table_id = get_u32(buf, off)?;
        let endpoint_af = decode_af(get_u8(buf, off)?);
        let endpoint: [u8; 16] = get_array(buf, off)?;
        let sw_if_index = get_u32(buf, off)?;
        let flags = get_u8(buf, off)?;
        let n = get_u8(buf, off)? as usize;
        let mut allowed_ips = Vec::with_capacity(n);
        for _ in 0..n {
            allowed_ips.push(WireguardAllowedIp::decode(buf, off)?);
        }
        Ok(Self {
            peer_index,
            public_key,
            port,
            persistent_keepalive,
            table_id,
            endpoint_af,
            endpoint,
            sw_if_index,
            flags,
            allowed_ips,
        })
    }
}

/// Create a wireguard interface. Reply carries the allocated
/// sw_if_index; the interface appears as `wg<user_instance>` (or
/// `wg<next-free>` when user_instance is ~0).
#[derive(Debug, Clone)]
pub struct WireguardInterfaceCreate {
    pub interface: WireguardInterface,
    pub generate_key: bool,
}

impl VppMessage for WireguardInterfaceCreate {
    const NAME: &'static str = "wireguard_interface_create";
    const CRC: &'static str = "a530137e";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        self.interface.encode(buf);
        put_u8(buf, self.generate_key as u8);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode(
            "wireguard_interface_create is send-only".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct WireguardInterfaceCreateReply {
    pub retval: i32,
    pub sw_if_index: u32,
}

impl VppMessage for WireguardInterfaceCreateReply {
    const NAME: &'static str = "wireguard_interface_create_reply";
    const CRC: &'static str = "5383d31f";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        let sw_if_index = get_u32(buf, &mut off)?;
        Ok(Self { retval, sw_if_index })
    }
}

#[derive(Debug, Clone)]
pub struct WireguardInterfaceDelete {
    pub sw_if_index: u32,
}

impl VppMessage for WireguardInterfaceDelete {
    const NAME: &'static str = "wireguard_interface_delete";
    const CRC: &'static str = "f9e6675e";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode(
            "wireguard_interface_delete is send-only".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct WireguardInterfaceDeleteReply {
    pub retval: i32,
}

impl VppMessage for WireguardInterfaceDeleteReply {
    const NAME: &'static str = "wireguard_interface_delete_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(Self { retval })
    }
}

/// Dump wireguard interfaces (details stream terminated by
/// control_ping like every VPP dump). sw_if_index ~0 = all.
#[derive(Debug, Clone)]
pub struct WireguardInterfaceDump {
    pub show_private_key: bool,
    pub sw_if_index: u32,
}

impl VppMessage for WireguardInterfaceDump {
    const NAME: &'static str = "wireguard_interface_dump";
    const CRC: &'static str = "2c954158";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.show_private_key as u8);
        put_u32(buf, self.sw_if_index);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode(
            "wireguard_interface_dump is send-only".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct WireguardInterfaceDetails {
    pub interface: WireguardInterface,
}

impl VppMessage for WireguardInterfaceDetails {
    const NAME: &'static str = "wireguard_interface_details";
    const CRC: &'static str = "0dd4865d";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let interface = WireguardInterface::decode(buf, &mut off)?;
        Ok(Self { interface })
    }
}

/// Add a peer to a wg interface. Adding an existing (same pubkey +
/// interface) peer returns the existing peer_index.
#[derive(Debug, Clone)]
pub struct WireguardPeerAdd {
    pub peer: WireguardPeer,
}

impl VppMessage for WireguardPeerAdd {
    const NAME: &'static str = "wireguard_peer_add";
    const CRC: &'static str = "9b8aad61";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        self.peer.encode(buf);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("wireguard_peer_add is send-only".into()))
    }
}

#[derive(Debug, Clone)]
pub struct WireguardPeerAddReply {
    pub retval: i32,
    pub peer_index: u32,
}

impl VppMessage for WireguardPeerAddReply {
    const NAME: &'static str = "wireguard_peer_add_reply";
    const CRC: &'static str = "084a0cd3";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        let peer_index = get_u32(buf, &mut off)?;
        Ok(Self { retval, peer_index })
    }
}

#[derive(Debug, Clone)]
pub struct WireguardPeerRemove {
    pub peer_index: u32,
}

impl VppMessage for WireguardPeerRemove {
    const NAME: &'static str = "wireguard_peer_remove";
    const CRC: &'static str = "3b74607a";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.peer_index);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode(
            "wireguard_peer_remove is send-only".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct WireguardPeerRemoveReply {
    pub retval: i32,
}

impl VppMessage for WireguardPeerRemoveReply {
    const NAME: &'static str = "wireguard_peer_remove_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(Self { retval })
    }
}

/// Dump peers. peer_index ~0 = all.
#[derive(Debug, Clone)]
pub struct WireguardPeersDump {
    pub peer_index: u32,
}

impl VppMessage for WireguardPeersDump {
    const NAME: &'static str = "wireguard_peers_dump";
    const CRC: &'static str = "3b74607a";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.peer_index);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("wireguard_peers_dump is send-only".into()))
    }
}

#[derive(Debug, Clone)]
pub struct WireguardPeersDetails {
    pub peer: WireguardPeer,
}

impl VppMessage for WireguardPeersDetails {
    const NAME: &'static str = "wireguard_peers_details";
    const CRC: &'static str = "6a9f6bc3";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let peer = WireguardPeer::decode(buf, &mut off)?;
        Ok(Self { peer })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_interface() -> WireguardInterface {
        let mut src = [0u8; 16];
        src[..4].copy_from_slice(&[10, 200, 0, 2]);
        WireguardInterface {
            user_instance: 0,
            sw_if_index: u32::MAX,
            private_key: [0x11; 32],
            public_key: [0; 32],
            port: 51820,
            src_af: AddressFamily::Ipv4,
            src_ip: src,
        }
    }

    #[test]
    fn interface_create_encode_layout() {
        let msg = WireguardInterfaceCreate {
            interface: sample_interface(),
            generate_key: false,
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 4 + 4 + 32 + 32 + 2 + 17 = 91 struct + 1 generate_key
        assert_eq!(buf.len(), 92);
        assert_eq!(&buf[0..4], &0u32.to_be_bytes()); // user_instance
        assert_eq!(&buf[4..8], &u32::MAX.to_be_bytes()); // sw_if_index
        assert_eq!(&buf[8..40], &[0x11; 32]); // private_key
        assert_eq!(&buf[72..74], &51820u16.to_be_bytes()); // port
        assert_eq!(buf[74], 0); // src af = v4
        assert_eq!(&buf[75..79], &[10, 200, 0, 2]);
        assert_eq!(buf[91], 0); // generate_key
    }

    #[test]
    fn interface_details_roundtrip() {
        let mut buf = Vec::new();
        sample_interface().encode(&mut buf);
        let d = WireguardInterfaceDetails::decode_fields(&buf).unwrap();
        assert_eq!(d.interface.port, 51820);
        assert_eq!(d.interface.private_key, [0x11; 32]);
        assert_eq!(d.interface.src_ip[..4], [10, 200, 0, 2]);
    }

    #[test]
    fn peer_encode_layout_and_roundtrip() {
        let mut ep = [0u8; 16];
        ep[..4].copy_from_slice(&[203, 0, 113, 5]);
        let peer = WireguardPeer {
            peer_index: u32::MAX,
            public_key: [0x22; 32],
            port: 51820,
            persistent_keepalive: 25,
            table_id: 0,
            endpoint_af: AddressFamily::Ipv4,
            endpoint: ep,
            sw_if_index: 3,
            flags: 0,
            allowed_ips: vec![
                WireguardAllowedIp::ipv4([10, 99, 0, 2], 32),
                WireguardAllowedIp::ipv4([192, 168, 50, 0], 24),
            ],
        };
        let mut buf = Vec::new();
        WireguardPeerAdd { peer: peer.clone() }.encode_fields(&mut buf);
        // 67 fixed + 2×18 allowed-ips
        assert_eq!(buf.len(), 67 + 36);
        assert_eq!(&buf[4..36], &[0x22; 32]); // public_key
        assert_eq!(&buf[36..38], &51820u16.to_be_bytes()); // port
        assert_eq!(&buf[38..40], &25u16.to_be_bytes()); // keepalive
        assert_eq!(&buf[40..44], &0u32.to_be_bytes()); // table_id
        assert_eq!(buf[44], 0); // endpoint af
        assert_eq!(&buf[45..49], &[203, 0, 113, 5]);
        assert_eq!(&buf[61..65], &3u32.to_be_bytes()); // sw_if_index
        assert_eq!(buf[65], 0); // flags
        assert_eq!(buf[66], 2); // n_allowed_ips
        assert_eq!(buf[66 + 18], 32); // first prefix len trailing byte

        let mut off = 0;
        let decoded = WireguardPeer::decode(&buf, &mut off).unwrap();
        assert_eq!(decoded.allowed_ips, peer.allowed_ips);
        assert_eq!(decoded.persistent_keepalive, 25);
    }
}
