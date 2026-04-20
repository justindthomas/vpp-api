//! VPP sfw plugin binary API.
//!
//! Wire format validated against the sfw plugin shipped with IMP at
//! the SHA pinned in scripts/external-daemon-versions.txt. These
//! bindings require the sfw plugin to be loaded in VPP.

use crate::error::VppError;
use crate::message::*;

/// Enable or disable the sfw feature arc on a single interface (both
/// ip4 and ip6 directions).
#[derive(Debug, Clone)]
pub struct SfwEnableDisable {
    pub enable_disable: bool,
    pub sw_if_index: u32,
}

impl VppMessage for SfwEnableDisable {
    const NAME: &'static str = "sfw_enable_disable";
    const CRC: &'static str = "3865946c";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.enable_disable as u8);
        put_u32(buf, self.sw_if_index);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("sfw_enable_disable is send-only".into()))
    }
}

#[derive(Debug, Clone)]
pub struct SfwEnableDisableReply {
    pub retval: i32,
}

impl VppMessage for SfwEnableDisableReply {
    const NAME: &'static str = "sfw_enable_disable_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(SfwEnableDisableReply { retval })
    }
}

/// Add or remove an interface from a named sfw zone. The zone is
/// created on first add; removal takes the interface back to the
/// unassigned state (zone_id=0) and disables the sfw feature arc.
///
/// Wire layout (after 10-byte request header):
///   is_add: u8
///   sw_if_index: u32
///   zone_name: [u8; 32]  (flat fixed-width NUL-padded)
#[derive(Debug, Clone)]
pub struct SfwZoneInterfaceAddDel {
    pub is_add: bool,
    pub sw_if_index: u32,
    pub zone_name: String,
}

impl VppMessage for SfwZoneInterfaceAddDel {
    const NAME: &'static str = "sfw_zone_interface_add_del";
    const CRC: &'static str = "66c8cf1c";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.is_add as u8);
        put_u32(buf, self.sw_if_index);
        let bytes = self.zone_name.as_bytes();
        let len = bytes.len().min(31);
        let mut pad = [0u8; 32];
        pad[..len].copy_from_slice(&bytes[..len]);
        buf.extend_from_slice(&pad);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode(
            "sfw_zone_interface_add_del is send-only".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct SfwZoneInterfaceAddDelReply {
    pub retval: i32,
}

impl VppMessage for SfwZoneInterfaceAddDelReply {
    const NAME: &'static str = "sfw_zone_interface_add_del_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(SfwZoneInterfaceAddDelReply { retval })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sfw_enable_disable_encode() {
        let msg = SfwEnableDisable {
            enable_disable: true,
            sw_if_index: 3,
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf[0], 1);
        assert_eq!(&buf[1..5], &3u32.to_be_bytes());
    }

    #[test]
    fn test_sfw_zone_encode() {
        let msg = SfwZoneInterfaceAddDel {
            is_add: true,
            sw_if_index: 7,
            zone_name: "external".to_string(),
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 1 (is_add) + 4 (sw_if_index) + 32 (zone_name) = 37
        assert_eq!(buf.len(), 37);
        assert_eq!(buf[0], 1);
        assert_eq!(&buf[1..5], &7u32.to_be_bytes());
        assert_eq!(&buf[5..13], b"external");
        assert!(buf[13..37].iter().all(|&b| b == 0));
    }
}
