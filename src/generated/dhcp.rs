//! VPP DHCP client API messages.
//!
//! Wire format validated against VPP 25.10 dhcp.api.json (v4 client)
//! and dhcp6_ia_na_client_cp.api.json (v6 client enable/disable).

use crate::error::VppError;
use crate::message::*;

/// DHCPv4 client configuration. Inner struct of dhcp_client_config.
///
/// Wire layout:
///   sw_if_index: u32
///   hostname: [u8; 64]  (NUL-padded string)
///   id: [u8; 64]        (opaque client id — VPP pads with zeros)
///   want_dhcp_event: u8
///   set_broadcast_flag: u8
///   dscp: u8
///   pid: u32
/// Total: 4 + 64 + 64 + 1 + 1 + 1 + 4 = 139 bytes
#[derive(Debug, Clone)]
pub struct DhcpClient {
    pub sw_if_index: u32,
    pub hostname: String,
    pub id: [u8; 64],
    pub want_dhcp_event: bool,
    pub set_broadcast_flag: bool,
    pub dscp: u8,
    pub pid: u32,
}

impl DhcpClient {
    /// Build a simple client record: hostname only, no custom id or
    /// event subscription. Matches VPP's `set dhcp client intfc X
    /// hostname Y` CLI shape.
    pub fn with_hostname(sw_if_index: u32, hostname: impl Into<String>) -> Self {
        Self {
            sw_if_index,
            hostname: hostname.into(),
            id: [0; 64],
            want_dhcp_event: false,
            set_broadcast_flag: true,
            dscp: 0,
            pid: std::process::id(),
        }
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
        // hostname: fixed 64-byte NUL-padded
        let bytes = self.hostname.as_bytes();
        let n = bytes.len().min(63);
        let mut name = [0u8; 64];
        name[..n].copy_from_slice(&bytes[..n]);
        put_bytes(buf, &name);
        put_bytes(buf, &self.id);
        put_u8(buf, self.want_dhcp_event as u8);
        put_u8(buf, self.set_broadcast_flag as u8);
        put_u8(buf, self.dscp);
        put_u32(buf, self.pid);
    }
}

/// Add or remove a DHCPv4 client on an interface.
#[derive(Debug, Clone)]
pub struct DhcpClientConfig {
    pub is_add: bool,
    pub client: DhcpClient,
}

impl VppMessage for DhcpClientConfig {
    const NAME: &'static str = "dhcp_client_config";
    const CRC: &'static str = "1af013ea";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.is_add as u8);
        self.client.encode(buf);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("dhcp_client_config is send-only".into()))
    }
}

#[derive(Debug, Clone)]
pub struct DhcpClientConfigReply {
    pub retval: i32,
}

impl VppMessage for DhcpClientConfigReply {
    const NAME: &'static str = "dhcp_client_config_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(DhcpClientConfigReply { retval })
    }
}

/// Enable or disable the DHCPv6 IA_NA client on an interface. Shares
/// the exact same wire shape (and CRC) as sw_interface_ip6_enable_disable
/// but is a distinct message name.
#[derive(Debug, Clone)]
pub struct Dhcp6ClientEnableDisable {
    pub sw_if_index: u32,
    pub enable: bool,
}

impl VppMessage for Dhcp6ClientEnableDisable {
    const NAME: &'static str = "dhcp6_client_enable_disable";
    const CRC: &'static str = "ae6cfcfb";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
        put_u8(buf, self.enable as u8);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode(
            "dhcp6_client_enable_disable is send-only".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct Dhcp6ClientEnableDisableReply {
    pub retval: i32,
}

impl VppMessage for Dhcp6ClientEnableDisableReply {
    const NAME: &'static str = "dhcp6_client_enable_disable_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(Dhcp6ClientEnableDisableReply { retval })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_client_config_encode() {
        let msg = DhcpClientConfig {
            is_add: true,
            client: DhcpClient::with_hostname(3, "router-wan"),
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 1 (is_add) + 4 (sw_if_index) + 64 (hostname) + 64 (id)
        //   + 1 + 1 + 1 (event/bcast/dscp) + 4 (pid) = 140
        assert_eq!(buf.len(), 140);
        assert_eq!(buf[0], 1); // is_add
        assert_eq!(&buf[1..5], &3u32.to_be_bytes());
        // First 10 bytes of the hostname field are "router-wan"
        assert_eq!(&buf[5..15], b"router-wan");
        // Rest of the 64-byte hostname slot is NUL
        assert!(buf[15..69].iter().all(|&b| b == 0));
        // 64-byte id default = zeros
        assert!(buf[69..133].iter().all(|&b| b == 0));
        assert_eq!(buf[133], 0); // want_dhcp_event=false
        assert_eq!(buf[134], 1); // set_broadcast_flag=true
        assert_eq!(buf[135], 0); // dscp=0
        // buf[136..140] = pid — not deterministic; just check length
    }

    #[test]
    fn test_dhcp_client_config_encode_remove() {
        let msg = DhcpClientConfig {
            is_add: false,
            client: DhcpClient::with_hostname(7, ""),
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        assert_eq!(buf[0], 0); // is_add=false
        assert_eq!(&buf[1..5], &7u32.to_be_bytes());
    }

    #[test]
    fn test_dhcp6_client_enable_encode() {
        let msg = Dhcp6ClientEnableDisable {
            sw_if_index: 5,
            enable: true,
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        assert_eq!(buf.len(), 5);
        assert_eq!(&buf[0..4], &5u32.to_be_bytes());
        assert_eq!(buf[4], 1);
    }
}
