//! VPP binary API wire format: framing and serialization.
//!
//! Every message on the socket is preceded by a 16-byte header:
//! - Bytes 0-3:  msgctx (u32 BE) — unused in socket transport, set to 0
//! - Bytes 4-7:  reserved (u32 BE) — set to 0
//! - Bytes 8-11: payload length (u32 BE)
//! - Bytes 12-15: reserved (u32 BE) — set to 0
//!
//! The payload is then:
//! - Bytes 0-1:  msg_id (u16 BE)
//! - Bytes 2-5:  client_index (u32 BE)
//! - Bytes 6-9:  context (u32 BE)
//! - Bytes 10+:  message-specific fields (big-endian packed)

use crate::VppError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Size of the framing header prepended to every message.
pub const HEADER_SIZE: usize = 16;

/// Size of the common request header (msg_id + client_index + context).
/// Used when sending messages from client to VPP.
pub const REQ_HEADER_SIZE: usize = 10;

/// Size of the common reply header (msg_id + context).
/// Used by VPP for all reply/detail/event messages.
pub const REPLY_HEADER_SIZE: usize = 6;

/// Encode a complete wire frame: 16-byte header + payload.
///
/// The payload should already contain [msg_id, client_index, context, fields...].
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(HEADER_SIZE + payload.len());
    // Bytes 0-3: msgctx (0)
    frame.extend_from_slice(&0u32.to_be_bytes());
    // Bytes 4-7: reserved (0)
    frame.extend_from_slice(&0u32.to_be_bytes());
    // Bytes 8-11: payload length
    frame.extend_from_slice(&len.to_be_bytes());
    // Bytes 12-15: reserved (0)
    frame.extend_from_slice(&0u32.to_be_bytes());
    // Payload
    frame.extend_from_slice(payload);
    frame
}

/// Build the common message header (msg_id + client_index + context).
pub fn encode_msg_header(msg_id: u16, client_index: u32, context: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(REQ_HEADER_SIZE);
    buf.extend_from_slice(&msg_id.to_be_bytes());
    buf.extend_from_slice(&client_index.to_be_bytes());
    buf.extend_from_slice(&context.to_be_bytes());
    buf
}

/// Read one complete frame from the socket.
///
/// Returns the payload (without the 16-byte framing header).
pub async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, VppError> {
    let mut header = [0u8; HEADER_SIZE];
    stream.read_exact(&mut header).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            VppError::ConnectionClosed
        } else {
            VppError::Io(e)
        }
    })?;

    // Bytes 8-11: payload length (BE u32)
    let payload_len =
        u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;

    if payload_len == 0 {
        return Ok(Vec::new());
    }

    // Sanity check: VPP messages shouldn't exceed ~64KB typically
    if payload_len > 1_048_576 {
        return Err(VppError::Decode(format!(
            "frame payload too large: {} bytes",
            payload_len
        )));
    }

    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            VppError::ConnectionClosed
        } else {
            VppError::Io(e)
        }
    })?;

    Ok(payload)
}

/// Write a complete frame to the socket.
pub async fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> Result<(), VppError> {
    let frame = encode_frame(payload);
    stream.write_all(&frame).await?;
    Ok(())
}

/// Parse a reply/detail/event header: msg_id(2) + context(4).
/// All messages FROM VPP use this layout (no client_index in the header).
pub fn parse_reply_header(payload: &[u8]) -> Result<(u16, u32), VppError> {
    if payload.len() < REPLY_HEADER_SIZE {
        return Err(VppError::Decode(format!(
            "payload too short for reply header: {} bytes",
            payload.len()
        )));
    }
    let msg_id = u16::from_be_bytes([payload[0], payload[1]]);
    let context = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
    Ok((msg_id, context))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_frame_roundtrip() {
        let payload = vec![0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let frame = encode_frame(&payload);

        assert_eq!(frame.len(), HEADER_SIZE + payload.len());
        // Bytes 8-11 should be payload length = 10
        assert_eq!(
            u32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]),
            10
        );
        // Payload should follow header
        assert_eq!(&frame[HEADER_SIZE..], &payload);
    }

    #[test]
    fn test_encode_msg_header() {
        let header = encode_msg_header(15, 0, 42);
        assert_eq!(header.len(), REQ_HEADER_SIZE);
        assert_eq!(u16::from_be_bytes([header[0], header[1]]), 15);
        assert_eq!(
            u32::from_be_bytes([header[2], header[3], header[4], header[5]]),
            0
        );
        assert_eq!(
            u32::from_be_bytes([header[6], header[7], header[8], header[9]]),
            42
        );
    }

    #[test]
    fn test_parse_reply_header() {
        // Reply header: msg_id(2) + context(4) = 6 bytes
        let mut payload = Vec::new();
        payload.extend_from_slice(&100u16.to_be_bytes());
        payload.extend_from_slice(&99u32.to_be_bytes());
        let (msg_id, context) = parse_reply_header(&payload).unwrap();
        assert_eq!(msg_id, 100);
        assert_eq!(context, 99);
    }

    #[test]
    fn test_parse_reply_header_too_short() {
        let short = vec![0u8; 3];
        assert!(parse_reply_header(&short).is_err());
    }
}
