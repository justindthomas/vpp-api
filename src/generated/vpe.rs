//! VPP Engine (VPE) messages: handshake and control.
//!
//! These messages are special — `sockclnt_create` uses hardcoded msg_id=15
//! since the message table hasn't been established yet.

use crate::error::VppError;
use crate::message::*;

/// Hardcoded message ID for `sockclnt_create` (before message table is available).
pub const SOCKCLNT_CREATE_MSG_ID: u16 = 15;

/// Sent by the client to establish a connection and receive the message table.
#[derive(Debug, Clone)]
pub struct SockclntCreate {
    /// Client name (max 63 bytes, NUL-padded to 64).
    pub name: String,
}

impl VppMessage for SockclntCreate {
    const NAME: &'static str = "sockclnt_create";
    const CRC: &'static str = "455fb9c4";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        // name: string[64] — fixed 64-byte NUL-padded field
        let name_bytes = self.name.as_bytes();
        let len = name_bytes.len().min(63);
        buf.extend_from_slice(&name_bytes[..len]);
        // Pad to 64 bytes
        for _ in len..64 {
            buf.push(0);
        }
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        // We never decode this — we only send it
        Err(VppError::Decode("sockclnt_create is send-only".into()))
    }
}

/// Entry in the message table returned during handshake.
#[derive(Debug, Clone)]
pub struct MessageTableEntry {
    /// Numeric message ID.
    pub index: u16,
    /// Message name including CRC suffix (e.g., "ip_route_add_del_b8ecfe0d").
    pub name: String,
}

/// Reply to `sockclnt_create` containing the assigned client index and message table.
#[derive(Debug, Clone)]
pub struct SockclntCreateReply {
    /// Response code (0 = success).
    pub response: i32,
    /// Assigned client index for all subsequent messages.
    pub index: u32,
    /// Number of entries in the message table.
    pub count: u16,
    /// The message table mapping names to runtime message IDs.
    pub message_table: Vec<MessageTableEntry>,
}

impl VppMessage for SockclntCreateReply {
    const NAME: &'static str = "sockclnt_create_reply";
    const CRC: &'static str = "35166268";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {
        // We never encode this — we only receive it
    }

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;

        let response = get_i32(buf, &mut off)?;
        let index = get_u32(buf, &mut off)?;
        let count = get_u16(buf, &mut off)?;

        let mut message_table = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let msg_index = get_u16(buf, &mut off)?;
            let name = get_string(buf, &mut off, 64)?;
            message_table.push(MessageTableEntry {
                index: msg_index,
                name,
            });
        }

        Ok(SockclntCreateReply {
            response,
            index,
            count,
            message_table,
        })
    }
}

/// Control ping — sent to keep the connection alive and as an end-of-dump marker.
#[derive(Debug, Clone)]
pub struct ControlPing;

impl VppMessage for ControlPing {
    const NAME: &'static str = "control_ping";
    const CRC: &'static str = "51077d14";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {
        // No additional fields
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Ok(ControlPing)
    }
}

/// Reply to control ping.
#[derive(Debug, Clone)]
pub struct ControlPingReply {
    /// Return value (0 = success).
    pub retval: i32,
    /// Client index.
    pub client_index: u32,
    /// VPP PID.
    pub vpe_pid: u32,
}

impl VppMessage for ControlPingReply {
    const NAME: &'static str = "control_ping_reply";
    const CRC: &'static str = "f6b0b8ca";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {
        // We only receive this
    }

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        let client_index = get_u32(buf, &mut off)?;
        let vpe_pid = get_u32(buf, &mut off)?;
        Ok(ControlPingReply {
            retval,
            client_index,
            vpe_pid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sockclnt_create_encode() {
        let msg = SockclntCreate {
            name: "imp-test".to_string(),
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        assert_eq!(buf.len(), 64);
        assert_eq!(&buf[..8], b"imp-test");
        assert!(buf[8..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_sockclnt_create_reply_decode() {
        // Build a minimal reply: response=0, index=1, count=2, two entries
        let mut buf = Vec::new();
        put_i32(&mut buf, 0); // response
        put_u32(&mut buf, 1); // index
        put_u16(&mut buf, 2); // count

        // Entry 1: index=100, name="control_ping_51077d14"
        put_u16(&mut buf, 100);
        let mut name1 = b"control_ping_51077d14".to_vec();
        name1.resize(64, 0);
        buf.extend_from_slice(&name1);

        // Entry 2: index=101, name="control_ping_reply_f6b0b8ca"
        put_u16(&mut buf, 101);
        let mut name2 = b"control_ping_reply_f6b0b8ca".to_vec();
        name2.resize(64, 0);
        buf.extend_from_slice(&name2);

        let reply = SockclntCreateReply::decode_fields(&buf).unwrap();
        assert_eq!(reply.response, 0);
        assert_eq!(reply.index, 1);
        assert_eq!(reply.count, 2);
        assert_eq!(reply.message_table.len(), 2);
        assert_eq!(reply.message_table[0].index, 100);
        assert_eq!(reply.message_table[0].name, "control_ping_51077d14");
        assert_eq!(reply.message_table[1].index, 101);
        assert_eq!(
            reply.message_table[1].name,
            "control_ping_reply_f6b0b8ca"
        );
    }

    #[test]
    fn test_control_ping_encode() {
        let msg = ControlPing;
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        assert!(buf.is_empty()); // No fields
    }

    #[test]
    fn test_control_ping_reply_decode() {
        let mut buf = Vec::new();
        put_i32(&mut buf, 0); // retval
        put_u32(&mut buf, 1); // client_index
        put_u32(&mut buf, 12345); // vpe_pid

        let reply = ControlPingReply::decode_fields(&buf).unwrap();
        assert_eq!(reply.retval, 0);
        assert_eq!(reply.client_index, 1);
        assert_eq!(reply.vpe_pid, 12345);
    }
}
