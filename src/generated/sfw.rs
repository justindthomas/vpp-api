//! VPP sfw plugin binary API.
//!
//! Wire format validated against the sfw plugin shipped with IMP at
//! the SHA pinned in scripts/external-daemon-versions.txt. These
//! bindings require the sfw plugin to be loaded in VPP.

use crate::error::VppError;
use crate::generated::ip::{AddressFamily, Prefix};
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

/// SFW rule / policy action codes. Mirrors `sfw_action_t` in sfw.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SfwAction {
    Deny = 0,
    Permit = 1,
    PermitStateful = 2,
    PermitStatefulNat = 3,
}

/// Rule address family filter. Mirrors `sfw_af_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SfwAf {
    Any = 0,
    Ip4 = 1,
    Ip6 = 2,
}

/// NAT pool mode. Mirrors `sfw_nat_mode_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SfwNatMode {
    Deterministic = 0,
    Dynamic = 1,
}

fn put_fixed_string(buf: &mut Vec<u8>, s: &str, n: usize) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(n.saturating_sub(1));
    let mut pad = vec![0u8; n];
    pad[..len].copy_from_slice(&bytes[..len]);
    buf.extend_from_slice(&pad);
}

/// Create or delete a policy.
///
/// Wire layout (after 10-byte request header):
///   is_add: u8
///   policy_name: [u8; 64]   (fixed NUL-padded)
///   from_zone:   [u8; 32]
///   to_zone:     [u8; 32]
///   default_action: u8      (SfwAction)
///   implicit_icmpv6: u8     (bool)
#[derive(Debug, Clone)]
pub struct SfwPolicyAddDel {
    pub is_add: bool,
    pub policy_name: String,
    pub from_zone: String,
    pub to_zone: String,
    pub default_action: SfwAction,
    pub implicit_icmpv6: bool,
}

impl VppMessage for SfwPolicyAddDel {
    const NAME: &'static str = "sfw_policy_add_del";
    const CRC: &'static str = "bb931f93";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.is_add as u8);
        put_fixed_string(buf, &self.policy_name, 64);
        put_fixed_string(buf, &self.from_zone, 32);
        put_fixed_string(buf, &self.to_zone, 32);
        put_u8(buf, self.default_action as u8);
        put_u8(buf, self.implicit_icmpv6 as u8);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("sfw_policy_add_del is send-only".into()))
    }
}

#[derive(Debug, Clone)]
pub struct SfwPolicyAddDelReply {
    pub retval: i32,
}

impl VppMessage for SfwPolicyAddDelReply {
    const NAME: &'static str = "sfw_policy_add_del_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(SfwPolicyAddDelReply { retval })
    }
}

/// Insert or remove a rule within a policy.
///
/// Wire layout:
///   is_add: u8
///   policy_name: [u8; 64]
///   rule_index: u32
///   action: u8  (SfwAction)
///   address_family: u8  (SfwAf)
///   src_prefix: vl_api_prefix_t (18 bytes)
///   dst_prefix: vl_api_prefix_t (18 bytes)
///   protocol: u8
///   src_port_lo: u16
///   src_port_hi: u16
///   dst_port_lo: u16
///   dst_port_hi: u16
///   icmp_type: u8
///   icmp_code: u8
#[derive(Debug, Clone)]
pub struct SfwPolicyRuleAddDel {
    pub is_add: bool,
    pub policy_name: String,
    pub rule_index: u32,
    pub action: SfwAction,
    pub address_family: SfwAf,
    pub src_prefix: Prefix,
    pub dst_prefix: Prefix,
    pub protocol: u8,
    pub src_port_lo: u16,
    pub src_port_hi: u16,
    pub dst_port_lo: u16,
    pub dst_port_hi: u16,
    pub icmp_type: u8,
    pub icmp_code: u8,
}

impl SfwPolicyRuleAddDel {
    /// Build a "match any" request suitable for add — caller tweaks
    /// the match fields. Any-family, any protocol, any ports, any
    /// icmp, zero prefix with /0.
    pub fn any(policy_name: impl Into<String>, rule_index: u32, action: SfwAction) -> Self {
        Self {
            is_add: true,
            policy_name: policy_name.into(),
            rule_index,
            action,
            address_family: SfwAf::Any,
            src_prefix: Prefix {
                af: AddressFamily::Ipv4,
                address: [0; 16],
                len: 0,
            },
            dst_prefix: Prefix {
                af: AddressFamily::Ipv4,
                address: [0; 16],
                len: 0,
            },
            protocol: 0,
            src_port_lo: 0,
            src_port_hi: 0,
            dst_port_lo: 0,
            dst_port_hi: 0,
            icmp_type: 255,
            icmp_code: 255,
        }
    }

    /// Delete the rule at `rule_index` in `policy_name`. Remaining
    /// fields are ignored by VPP on del.
    pub fn del(policy_name: impl Into<String>, rule_index: u32) -> Self {
        let mut r = Self::any(policy_name, rule_index, SfwAction::Deny);
        r.is_add = false;
        r
    }
}

impl VppMessage for SfwPolicyRuleAddDel {
    const NAME: &'static str = "sfw_policy_rule_add_del";
    const CRC: &'static str = "2fa9c963";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.is_add as u8);
        put_fixed_string(buf, &self.policy_name, 64);
        put_u32(buf, self.rule_index);
        put_u8(buf, self.action as u8);
        put_u8(buf, self.address_family as u8);
        self.src_prefix.encode(buf);
        self.dst_prefix.encode(buf);
        put_u8(buf, self.protocol);
        put_u16(buf, self.src_port_lo);
        put_u16(buf, self.src_port_hi);
        put_u16(buf, self.dst_port_lo);
        put_u16(buf, self.dst_port_hi);
        put_u8(buf, self.icmp_type);
        put_u8(buf, self.icmp_code);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode(
            "sfw_policy_rule_add_del is send-only".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct SfwPolicyRuleAddDelReply {
    pub retval: i32,
}

impl VppMessage for SfwPolicyRuleAddDelReply {
    const NAME: &'static str = "sfw_policy_rule_add_del_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(SfwPolicyRuleAddDelReply { retval })
    }
}

/// Create or delete an IPv4 NAT pool.
///
/// Wire layout:
///   is_add: u8
///   external_prefix: vl_api_prefix_t (18)
///   internal_prefix: vl_api_prefix_t (18)
///   mode: u8
#[derive(Debug, Clone)]
pub struct SfwNatPoolAddDel {
    pub is_add: bool,
    pub external_prefix: Prefix,
    pub internal_prefix: Prefix,
    pub mode: SfwNatMode,
}

impl VppMessage for SfwNatPoolAddDel {
    const NAME: &'static str = "sfw_nat_pool_add_del";
    const CRC: &'static str = "104621ad";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.is_add as u8);
        self.external_prefix.encode(buf);
        self.internal_prefix.encode(buf);
        put_u8(buf, self.mode as u8);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("sfw_nat_pool_add_del is send-only".into()))
    }
}

#[derive(Debug, Clone)]
pub struct SfwNatPoolAddDelReply {
    pub retval: i32,
}

impl VppMessage for SfwNatPoolAddDelReply {
    const NAME: &'static str = "sfw_nat_pool_add_del_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(SfwNatPoolAddDelReply { retval })
    }
}

/// Create or delete a static (DNAT) mapping.
///
/// Wire layout:
///   is_add: u8
///   external_address: vl_api_address_t (17)
///   internal_address: vl_api_address_t (17)
///   protocol: u8 (0 = 1:1, 6 = TCP, 17 = UDP)
///   external_port: u16
///   internal_port: u16
///
/// vl_api_address_t is af(u8) + un(16 bytes) — same layout as a
/// Prefix sans the trailing `len` field. We reuse the ip4/ip6
/// helpers for clarity.
#[derive(Debug, Clone)]
pub struct SfwNatStaticAddDel {
    pub is_add: bool,
    pub external_af: AddressFamily,
    pub external_address: [u8; 16],
    pub internal_af: AddressFamily,
    pub internal_address: [u8; 16],
    pub protocol: u8,
    pub external_port: u16,
    pub internal_port: u16,
}

impl SfwNatStaticAddDel {
    pub fn one_to_one_ipv4(ext: [u8; 4], int: [u8; 4], is_add: bool) -> Self {
        let mut ext16 = [0u8; 16];
        ext16[..4].copy_from_slice(&ext);
        let mut int16 = [0u8; 16];
        int16[..4].copy_from_slice(&int);
        Self {
            is_add,
            external_af: AddressFamily::Ipv4,
            external_address: ext16,
            internal_af: AddressFamily::Ipv4,
            internal_address: int16,
            protocol: 0,
            external_port: 0,
            internal_port: 0,
        }
    }
}

impl VppMessage for SfwNatStaticAddDel {
    const NAME: &'static str = "sfw_nat_static_add_del";
    const CRC: &'static str = "1ea19567";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.is_add as u8);
        put_u8(buf, self.external_af as u8);
        buf.extend_from_slice(&self.external_address);
        put_u8(buf, self.internal_af as u8);
        buf.extend_from_slice(&self.internal_address);
        put_u8(buf, self.protocol);
        put_u16(buf, self.external_port);
        put_u16(buf, self.internal_port);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("sfw_nat_static_add_del is send-only".into()))
    }
}

#[derive(Debug, Clone)]
pub struct SfwNatStaticAddDelReply {
    pub retval: i32,
}

impl VppMessage for SfwNatStaticAddDelReply {
    const NAME: &'static str = "sfw_nat_static_add_del_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(SfwNatStaticAddDelReply { retval })
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

    #[test]
    fn test_sfw_policy_add_encode() {
        let msg = SfwPolicyAddDel {
            is_add: true,
            policy_name: "ext_to_int".to_string(),
            from_zone: "external".to_string(),
            to_zone: "internal".to_string(),
            default_action: SfwAction::Deny,
            implicit_icmpv6: true,
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 1 (is_add) + 64 (policy_name) + 32 (from) + 32 (to)
        //   + 1 (default_action) + 1 (implicit_icmpv6) = 131
        assert_eq!(buf.len(), 131);
        assert_eq!(buf[0], 1);
        assert_eq!(&buf[1..11], b"ext_to_int");
        assert_eq!(&buf[65..73], b"external");
        assert_eq!(&buf[97..105], b"internal");
        assert_eq!(buf[129], 0); // deny
        assert_eq!(buf[130], 1); // implicit_icmpv6
    }

    #[test]
    fn test_sfw_policy_rule_encode() {
        let msg = SfwPolicyRuleAddDel::any("p", 0, SfwAction::Permit);
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 1+64+4+1+1+18+18+1+2+2+2+2+1+1 = 118
        assert_eq!(buf.len(), 118);
        assert_eq!(buf[0], 1); // is_add
        assert_eq!(&buf[1..2], b"p");
        assert!(buf[2..65].iter().all(|&b| b == 0)); // rest of policy_name
        assert_eq!(&buf[65..69], &0u32.to_be_bytes()); // rule_index
        assert_eq!(buf[69], 1); // permit
        assert_eq!(buf[70], 0); // af any
        assert_eq!(buf[116], 255); // icmp_type any
        assert_eq!(buf[117], 255); // icmp_code any
    }

    #[test]
    fn test_sfw_nat_pool_encode() {
        let msg = SfwNatPoolAddDel {
            is_add: true,
            external_prefix: Prefix::ipv4([203, 0, 113, 0], 24),
            internal_prefix: Prefix::ipv4([10, 0, 0, 0], 24),
            mode: SfwNatMode::Dynamic,
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 1 + 18 + 18 + 1 = 38
        assert_eq!(buf.len(), 38);
        assert_eq!(buf[0], 1);
        assert_eq!(buf[1], 0); // v4
        assert_eq!(&buf[2..6], &[203, 0, 113, 0]);
        assert_eq!(buf[18], 24);
        assert_eq!(buf[37], 1); // dynamic
    }

    #[test]
    fn test_sfw_nat_static_1to1_encode() {
        let msg = SfwNatStaticAddDel::one_to_one_ipv4([198, 51, 100, 1], [192, 168, 1, 10], true);
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 1 + 17 + 17 + 1 + 2 + 2 = 40
        assert_eq!(buf.len(), 40);
        assert_eq!(buf[0], 1); // is_add
        assert_eq!(buf[1], 0); // ext af v4
        assert_eq!(&buf[2..6], &[198, 51, 100, 1]);
        assert_eq!(buf[18], 0); // int af v4
        assert_eq!(&buf[19..23], &[192, 168, 1, 10]);
        assert_eq!(buf[35], 0); // protocol = 0 (1:1)
        assert_eq!(&buf[36..38], &0u16.to_be_bytes());
        assert_eq!(&buf[38..40], &0u16.to_be_bytes());
    }
}
