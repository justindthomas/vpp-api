//! VPP IPv6 ND / Router Advertisement API messages.
//!
//! Wire format validated against VPP 25.10
//! `api-json/core/ip6_nd.api.json`.
//!
//! Covers:
//! - `sw_interface_ip6nd_ra_config` — per-interface RA parameters
//!   (M/O flags, intervals, router lifetime, suppress, etc.)
//! - `sw_interface_ip6nd_ra_prefix` — per-prefix RA settings
//!   (valid/preferred lifetimes, L/A flags)
//!
//! Together these replace the `vppctl ip6 nd …` shell-outs that
//! used to live in `vpp-core-config.sh` (impd's post-VPP-init
//! script). impd's `sync_ipv6_ra_via_api` walks every parent with
//! `ipv6_ra.enabled` and issues these two messages directly.

use crate::error::VppError;
use crate::generated::ip::Prefix;
use crate::message::*;

/// Per-interface IPv6 Router Advertisement configuration.
///
/// CRC: 0x3eb00b1c. Fields after the common header:
/// ```text
///   sw_if_index:       u32  (vl_api_interface_index_t)
///   suppress:          u8   (1 = stop emitting unsolicited RAs)
///   managed:           u8   (M-bit — clients should use DHCPv6 for addresses)
///   other:             u8   (O-bit — clients should use DHCPv6 for other config)
///   ll_option:         u8   (include source-link-layer-address option)
///   send_unicast:      u8   (send unicast RAs to solicitations rather than mcast)
///   cease:             u8   (send final lifetime=0 RA and stop)
///   is_no:             bool (1 = remove RA config)
///   default_router:    u8   (advertise self as default router)
///   max_interval:      u32  (seconds — max between unsolicited RAs)
///   min_interval:      u32  (seconds — min between unsolicited RAs)
///   lifetime:          u32  (router lifetime; 0 = not a default router)
///   initial_count:     u32  (initial rapid RAs after up)
///   initial_interval:  u32  (seconds between the initial RAs)
/// ```
#[derive(Debug, Clone, Default)]
pub struct SwInterfaceIp6NdRaConfig {
    pub sw_if_index: u32,
    pub suppress: u8,
    pub managed: u8,
    pub other: u8,
    pub ll_option: u8,
    pub send_unicast: u8,
    pub cease: u8,
    pub is_no: bool,
    pub default_router: u8,
    pub max_interval: u32,
    pub min_interval: u32,
    pub lifetime: u32,
    pub initial_count: u32,
    pub initial_interval: u32,
}

impl VppMessage for SwInterfaceIp6NdRaConfig {
    const NAME: &'static str = "sw_interface_ip6nd_ra_config";
    const CRC: &'static str = "3eb00b1c";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
        put_u8(buf, self.suppress);
        put_u8(buf, self.managed);
        put_u8(buf, self.other);
        put_u8(buf, self.ll_option);
        put_u8(buf, self.send_unicast);
        put_u8(buf, self.cease);
        put_u8(buf, if self.is_no { 1 } else { 0 });
        put_u8(buf, self.default_router);
        put_u32(buf, self.max_interval);
        put_u32(buf, self.min_interval);
        put_u32(buf, self.lifetime);
        put_u32(buf, self.initial_count);
        put_u32(buf, self.initial_interval);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode(
            "sw_interface_ip6nd_ra_config is send-only".into(),
        ))
    }
}

/// Reply to `SwInterfaceIp6NdRaConfig`. Carries only `retval`.
#[derive(Debug, Clone, Default)]
pub struct SwInterfaceIp6NdRaConfigReply {
    pub retval: i32,
}

impl VppMessage for SwInterfaceIp6NdRaConfigReply {
    const NAME: &'static str = "sw_interface_ip6nd_ra_config_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_i32(buf, self.retval);
    }

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(SwInterfaceIp6NdRaConfigReply { retval })
    }
}

/// Per-prefix IPv6 RA configuration.
///
/// CRC: 0x82cc1b28. Fields after the common header:
/// ```text
///   sw_if_index:    u32                (vl_api_interface_index_t)
///   prefix:         vl_api_prefix_t    (af + 16 bytes + len = 18 bytes)
///   use_default:    bool               (revert to defaults — ignores the other bools)
///   no_advertise:   bool               (suppress this prefix only)
///   off_link:       bool               (clears L-flag)
///   no_autoconfig:  bool               (clears A-flag)
///   no_onlink:      bool               (consistency partner for off_link)
///   is_no:          bool               (delete the prefix entry)
///   val_lifetime:   u32                (seconds; 0xffffffff = infinity)
///   pref_lifetime:  u32                (seconds; 0xffffffff = infinity;
///                                       MUST NOT exceed val_lifetime — RFC 4861 §6.2.1)
/// ```
#[derive(Debug, Clone)]
pub struct SwInterfaceIp6NdRaPrefix {
    pub sw_if_index: u32,
    pub prefix: Prefix,
    pub use_default: bool,
    pub no_advertise: bool,
    pub off_link: bool,
    pub no_autoconfig: bool,
    pub no_onlink: bool,
    pub is_no: bool,
    pub val_lifetime: u32,
    pub pref_lifetime: u32,
}

impl VppMessage for SwInterfaceIp6NdRaPrefix {
    const NAME: &'static str = "sw_interface_ip6nd_ra_prefix";
    const CRC: &'static str = "82cc1b28";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
        self.prefix.encode(buf);
        put_u8(buf, if self.use_default { 1 } else { 0 });
        put_u8(buf, if self.no_advertise { 1 } else { 0 });
        put_u8(buf, if self.off_link { 1 } else { 0 });
        put_u8(buf, if self.no_autoconfig { 1 } else { 0 });
        put_u8(buf, if self.no_onlink { 1 } else { 0 });
        put_u8(buf, if self.is_no { 1 } else { 0 });
        put_u32(buf, self.val_lifetime);
        put_u32(buf, self.pref_lifetime);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode(
            "sw_interface_ip6nd_ra_prefix is send-only".into(),
        ))
    }
}

/// Reply to `SwInterfaceIp6NdRaPrefix`. Carries only `retval`.
#[derive(Debug, Clone, Default)]
pub struct SwInterfaceIp6NdRaPrefixReply {
    pub retval: i32,
}

impl VppMessage for SwInterfaceIp6NdRaPrefixReply {
    const NAME: &'static str = "sw_interface_ip6nd_ra_prefix_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_i32(buf, self.retval);
    }

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(SwInterfaceIp6NdRaPrefixReply { retval })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ra_config_encodes_32_byte_payload() {
        // sw_if_index(4) + 7 single-byte flags + default_router(1) + 5 u32s(20)
        // = 4 + 8 + 20 = 32 bytes after the common header.
        let m = SwInterfaceIp6NdRaConfig {
            sw_if_index: 7,
            suppress: 0,
            managed: 1,
            other: 0,
            ll_option: 0,
            send_unicast: 0,
            cease: 0,
            is_no: false,
            default_router: 0,
            max_interval: 30,
            min_interval: 15,
            lifetime: 600,
            initial_count: 3,
            initial_interval: 16,
        };
        let mut buf = Vec::new();
        m.encode_fields(&mut buf);
        assert_eq!(buf.len(), 32, "unexpected encoded length: {:?}", buf);
        // sw_if_index = 7 (big-endian u32)
        assert_eq!(&buf[0..4], &[0, 0, 0, 7]);
        // managed flag at offset 5 (after sw_if_index + suppress)
        assert_eq!(buf[5], 1);
        // max_interval = 30 at offset 12 (after 8 single-byte flags)
        assert_eq!(&buf[12..16], &[0, 0, 0, 30]);
    }

    #[test]
    fn ra_prefix_encodes_with_prefix_inline() {
        // sw_if_index(4) + prefix(18) + 6 bools(6) + 2 u32s(8) = 36 bytes.
        let prefix = Prefix::ipv6(
            [
                0x26, 0x02, 0xf9, 0x0e, 0, 0x10, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
            64,
        );
        let m = SwInterfaceIp6NdRaPrefix {
            sw_if_index: 15,
            prefix,
            use_default: false,
            no_advertise: false,
            off_link: false,
            no_autoconfig: false,
            no_onlink: false,
            is_no: false,
            val_lifetime: 2_592_000,
            pref_lifetime: 604_800,
        };
        let mut buf = Vec::new();
        m.encode_fields(&mut buf);
        assert_eq!(buf.len(), 36, "unexpected encoded length: {:?}", buf);
        // sw_if_index at the start.
        assert_eq!(&buf[0..4], &[0, 0, 0, 15]);
        // af = 1 (Ipv6) at offset 4.
        assert_eq!(buf[4], 1);
        // prefix length = 64 at offset 4+1+16 = 21.
        assert_eq!(buf[21], 64);
        // val_lifetime at offset 28 (after 6 bools).
        assert_eq!(&buf[28..32], &2_592_000u32.to_be_bytes());
        // pref_lifetime at offset 32.
        assert_eq!(&buf[32..36], &604_800u32.to_be_bytes());
    }

    #[test]
    fn ra_prefix_reply_decodes_retval() {
        let buf = (-7i32).to_be_bytes();
        let r = SwInterfaceIp6NdRaPrefixReply::decode_fields(&buf).unwrap();
        assert_eq!(r.retval, -7);
    }
}
