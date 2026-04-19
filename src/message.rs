/// Trait implemented by all VPP API message types.
///
/// Each message has a name and CRC that together form a unique key
/// used to look up the runtime message ID during the handshake.
/// The encode/decode methods handle big-endian wire serialization.
pub trait VppMessage: Sized + Send + 'static {
    /// Message name as it appears in VPP's API (e.g., "ip_route_add_del").
    const NAME: &'static str;

    /// CRC suffix for version matching (e.g., "b8ecfe0d").
    const CRC: &'static str;

    /// Returns the combined name_CRC string used for message table lookup.
    fn name_crc() -> String {
        format!("{}_{}", Self::NAME, Self::CRC)
    }

    /// Encode this message's fields (after the common header) into the buffer.
    /// The common header (msg_id, client_index, context) is written by the client.
    fn encode_fields(&self, buf: &mut Vec<u8>);

    /// Decode this message's fields from the buffer (starting after the common header).
    fn decode_fields(buf: &[u8]) -> Result<Self, crate::VppError>;
}

/// Helper to write a u8 to a buffer.
#[inline]
pub fn put_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}

/// Helper to write a u16 big-endian to a buffer.
#[inline]
pub fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Helper to write a u32 big-endian to a buffer.
#[inline]
pub fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Helper to write an i32 big-endian to a buffer.
#[inline]
pub fn put_i32(buf: &mut Vec<u8>, v: i32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Helper to write a u64 big-endian to a buffer.
#[inline]
pub fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Helper to write a fixed-length byte array to a buffer.
#[inline]
pub fn put_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(data);
}

/// Helper to read a u8 from a slice at an offset, advancing the offset.
#[inline]
pub fn get_u8(buf: &[u8], off: &mut usize) -> Result<u8, crate::VppError> {
    if *off >= buf.len() {
        return Err(crate::VppError::Decode("buffer underflow reading u8".into()));
    }
    let v = buf[*off];
    *off += 1;
    Ok(v)
}

/// Helper to read a u16 big-endian from a slice at an offset.
#[inline]
pub fn get_u16(buf: &[u8], off: &mut usize) -> Result<u16, crate::VppError> {
    if *off + 2 > buf.len() {
        return Err(crate::VppError::Decode("buffer underflow reading u16".into()));
    }
    let v = u16::from_be_bytes([buf[*off], buf[*off + 1]]);
    *off += 2;
    Ok(v)
}

/// Helper to read a u32 big-endian from a slice at an offset.
#[inline]
pub fn get_u32(buf: &[u8], off: &mut usize) -> Result<u32, crate::VppError> {
    if *off + 4 > buf.len() {
        return Err(crate::VppError::Decode("buffer underflow reading u32".into()));
    }
    let v = u32::from_be_bytes([buf[*off], buf[*off + 1], buf[*off + 2], buf[*off + 3]]);
    *off += 4;
    Ok(v)
}

/// Helper to read an i32 big-endian from a slice at an offset.
#[inline]
pub fn get_i32(buf: &[u8], off: &mut usize) -> Result<i32, crate::VppError> {
    if *off + 4 > buf.len() {
        return Err(crate::VppError::Decode("buffer underflow reading i32".into()));
    }
    let v = i32::from_be_bytes([buf[*off], buf[*off + 1], buf[*off + 2], buf[*off + 3]]);
    *off += 4;
    Ok(v)
}

/// Helper to read a u64 big-endian from a slice at an offset.
#[inline]
pub fn get_u64(buf: &[u8], off: &mut usize) -> Result<u64, crate::VppError> {
    if *off + 8 > buf.len() {
        return Err(crate::VppError::Decode("buffer underflow reading u64".into()));
    }
    let v = u64::from_be_bytes([
        buf[*off],
        buf[*off + 1],
        buf[*off + 2],
        buf[*off + 3],
        buf[*off + 4],
        buf[*off + 5],
        buf[*off + 6],
        buf[*off + 7],
    ]);
    *off += 8;
    Ok(v)
}

/// Helper to read N bytes from a slice at an offset.
#[inline]
pub fn get_bytes(buf: &[u8], off: &mut usize, n: usize) -> Result<Vec<u8>, crate::VppError> {
    if *off + n > buf.len() {
        return Err(crate::VppError::Decode(format!(
            "buffer underflow reading {} bytes",
            n
        )));
    }
    let v = buf[*off..*off + n].to_vec();
    *off += n;
    Ok(v)
}

/// Helper to read a fixed-size array from a slice at an offset.
#[inline]
pub fn get_array<const N: usize>(
    buf: &[u8],
    off: &mut usize,
) -> Result<[u8; N], crate::VppError> {
    if *off + N > buf.len() {
        return Err(crate::VppError::Decode(format!(
            "buffer underflow reading [u8; {}]",
            N
        )));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&buf[*off..*off + N]);
    *off += N;
    Ok(arr)
}

/// Helper to read a NUL-terminated string from a fixed-size field.
pub fn get_string(buf: &[u8], off: &mut usize, max_len: usize) -> Result<String, crate::VppError> {
    let bytes = get_bytes(buf, off, max_len)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(max_len);
    String::from_utf8(bytes[..end].to_vec())
        .map_err(|e| crate::VppError::Decode(format!("invalid UTF-8: {}", e)))
}
