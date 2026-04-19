//! VPP punt socket API messages.
//!
//! Wire format validated against VPP 25.10 punt.api.json.
//!
//! Punt sockets allow external processes to receive control plane packets
//! that match specific criteria (IP protocol, UDP port, etc.).

use crate::error::VppError;
use crate::message::*;

/// Punt type (u32 enum).
/// Note: L4=0, IP_PROTO=1, EXCEPTION=2 (not 1,2,3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PuntType {
    L4 = 0,
    IpProto = 1,
    Exception = 2,
}

/// Encode a `punt_t` on the wire.
///
/// punt_t layout:
///   type: u32 (punt_type enum)
///   punt: punt_union_t (union of exception/l4/ip_proto)
///
/// The union is sized to the largest variant. Let's figure out sizes:
///   punt_exception_t: id(u32) = 4 bytes
///   punt_l4_t: af(u8) + protocol(u8) + port(u16) = 4 bytes
///   punt_ip_proto_t: af(u8) + protocol(u8) = 2 bytes
///
/// Union size = max(4, 4, 2) = 4 bytes.
/// Total punt_t = 4 (type) + 4 (union) = 8 bytes.
fn encode_punt(buf: &mut Vec<u8>, punt_type: PuntType, af: u8, protocol: u8, port: u16) {
    put_u32(buf, punt_type as u32);
    match punt_type {
        PuntType::L4 => {
            // punt_l4_t: af(u8) + protocol(u8) + port(u16)
            put_u8(buf, af);
            put_u8(buf, protocol);
            put_u16(buf, port);
        }
        PuntType::IpProto => {
            // punt_ip_proto_t: af(u8) + protocol(u8)
            put_u8(buf, af);
            put_u8(buf, protocol);
            // Pad to union size (4 bytes)
            put_u16(buf, 0);
        }
        PuntType::Exception => {
            // punt_exception_t: id(u32)
            put_u32(buf, 0);
        }
    }
}

/// Register a punt socket to receive matching packets.
///
/// Fields (after common header):
///   header_version: u32
///   punt: punt_t (8 bytes)
///   pathname: string[108] (fixed-size NUL-padded)
#[derive(Debug, Clone)]
pub struct PuntSocketRegister {
    pub header_version: u32,
    pub punt_type: PuntType,
    /// Address family: 0=IPv4, 1=IPv6 (u8).
    pub af: u8,
    /// IP protocol number (e.g., 89 for OSPF) or L4 protocol.
    pub protocol: u8,
    /// Port number (for L4 type only).
    pub port: u16,
    /// Unix socket pathname to receive packets on (max 107 chars + NUL).
    pub pathname: String,
}

impl VppMessage for PuntSocketRegister {
    const NAME: &'static str = "punt_socket_register";
    const CRC: &'static str = "7875badb";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.header_version);
        encode_punt(buf, self.punt_type, self.af, self.protocol, self.port);
        // pathname: string[108] — fixed 108-byte NUL-padded
        let path_bytes = self.pathname.as_bytes();
        let len = path_bytes.len().min(107);
        let mut path_buf = [0u8; 108];
        path_buf[..len].copy_from_slice(&path_bytes[..len]);
        put_bytes(buf, &path_buf);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("punt_socket_register is send-only".into()))
    }
}

/// Reply to punt_socket_register.
///
/// Fields (after common header):
///   retval: i32
///   pathname: string[108]
#[derive(Debug, Clone)]
pub struct PuntSocketRegisterReply {
    pub retval: i32,
    /// Pathname of VPP's socket for TX (sending packets back).
    pub pathname: String,
}

impl VppMessage for PuntSocketRegisterReply {
    const NAME: &'static str = "punt_socket_register_reply";
    const CRC: &'static str = "bd30ae90";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        let pathname = get_string(buf, &mut off, 108)?;
        Ok(PuntSocketRegisterReply { retval, pathname })
    }
}

/// Deregister a punt socket.
///
/// Fields (after common header):
///   punt: punt_t (8 bytes)
#[derive(Debug, Clone)]
pub struct PuntSocketDeregister {
    pub punt_type: PuntType,
    pub af: u8,
    pub protocol: u8,
    pub port: u16,
}

impl VppMessage for PuntSocketDeregister {
    const NAME: &'static str = "punt_socket_deregister";
    const CRC: &'static str = "75afa766";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        encode_punt(buf, self.punt_type, self.af, self.protocol, self.port);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode(
            "punt_socket_deregister is send-only".into(),
        ))
    }
}

/// Reply to punt_socket_deregister.
#[derive(Debug, Clone)]
pub struct PuntSocketDeregisterReply {
    pub retval: i32,
}

impl VppMessage for PuntSocketDeregisterReply {
    const NAME: &'static str = "punt_socket_deregister_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(PuntSocketDeregisterReply { retval })
    }
}
