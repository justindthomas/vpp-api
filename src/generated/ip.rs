//! VPP IP route API messages.
//!
//! Core messages for FIB programming: ip_route_add_del and ip_route_dump.

use crate::error::VppError;
use crate::message::*;

/// Address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressFamily {
    Ipv4 = 0,
    Ipv6 = 1,
}

/// IP prefix: address family + address bytes + prefix length.
#[derive(Debug, Clone)]
pub struct Prefix {
    pub af: AddressFamily,
    /// IPv4: 4 bytes (right-padded to 16), IPv6: 16 bytes.
    pub address: [u8; 16],
    pub len: u8,
}

impl Prefix {
    pub fn ipv4(addr: [u8; 4], len: u8) -> Self {
        let mut address = [0u8; 16];
        address[..4].copy_from_slice(&addr);
        Self {
            af: AddressFamily::Ipv4,
            address,
            len,
        }
    }

    pub fn ipv6(addr: [u8; 16], len: u8) -> Self {
        Self {
            af: AddressFamily::Ipv6,
            address: addr,
            len,
        }
    }
}

impl Prefix {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        // address: vl_api_address_t = af(u8) + un(16 bytes)
        put_u8(buf, self.af as u8);
        put_bytes(buf, &self.address);
        put_u8(buf, self.len);
    }

    pub fn decode(buf: &[u8], off: &mut usize) -> Result<Self, VppError> {
        let af_val = get_u8(buf, off)?;
        let af = match af_val {
            0 => AddressFamily::Ipv4,
            1 => AddressFamily::Ipv6,
            _ => return Err(VppError::Decode(format!("unknown address family: {}", af_val))),
        };
        let address = get_array::<16>(buf, off)?;
        let len = get_u8(buf, off)?;
        Ok(Prefix { af, address, len })
    }
}

/// FIB path type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FibPathType {
    Normal = 0,
    Local = 1,
    Drop = 2,
    UdpEncap = 3,
    Bier = 4,
    IcmpUnreach = 5,
    IcmpProhibit = 6,
    SourceLookup = 7,
    Dvr = 8,
    InterfaceRx = 9,
    Classify = 10,
}

/// FIB path NH protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FibPathNhProto {
    Ip4 = 0,
    Ip6 = 1,
    Mpls = 2,
    Ethernet = 3,
    Bier = 4,
}

/// A next-hop path in a FIB entry.
#[derive(Debug, Clone)]
pub struct FibPath {
    pub sw_if_index: u32,
    pub table_id: u32,
    pub rpf_id: u32,
    pub weight: u8,
    pub preference: u8,
    pub path_type: u32,
    pub flags: u32,
    pub proto: u32,
    /// Next-hop address (16 bytes — IPv4 uses first 4).
    pub nh_addr: [u8; 16],
    pub nh_via_label: u32,
    pub nh_obj_id: u32,
    pub nh_classify_table_index: u32,
    pub n_labels: u8,
    pub label_stack: Vec<u32>, // Up to 16 labels
}

impl Default for FibPath {
    fn default() -> Self {
        Self {
            sw_if_index: u32::MAX, // ~0 = unset
            table_id: 0,
            rpf_id: u32::MAX,
            weight: 1,
            preference: 0,
            path_type: FibPathType::Normal as u32,
            flags: 0,
            proto: FibPathNhProto::Ip4 as u32,
            nh_addr: [0; 16],
            nh_via_label: 0,
            nh_obj_id: u32::MAX,
            nh_classify_table_index: u32::MAX,
            n_labels: 0,
            label_stack: Vec::new(),
        }
    }
}

impl FibPath {
    /// Create a simple IPv4 next-hop path.
    pub fn via_ipv4(addr: [u8; 4], sw_if_index: u32) -> Self {
        let mut nh_addr = [0u8; 16];
        nh_addr[..4].copy_from_slice(&addr);
        Self {
            sw_if_index,
            proto: FibPathNhProto::Ip4 as u32,
            nh_addr,
            ..Default::default()
        }
    }

    /// Create a simple IPv6 next-hop path.
    pub fn via_ipv6(addr: [u8; 16], sw_if_index: u32) -> Self {
        Self {
            sw_if_index,
            proto: FibPathNhProto::Ip6 as u32,
            nh_addr: addr,
            ..Default::default()
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
        put_u32(buf, self.table_id);
        put_u32(buf, self.rpf_id);
        put_u8(buf, self.weight);
        put_u8(buf, self.preference);
        put_u32(buf, self.path_type);
        put_u32(buf, self.flags);
        put_u32(buf, self.proto);
        // fib_path_nh_t (struct, NOT union):
        //   address: address_union_t (16 bytes)
        //   via_label: u32
        //   obj_id: u32
        //   classify_table_index: u32
        // Total: 28 bytes
        put_bytes(buf, &self.nh_addr);
        put_u32(buf, self.nh_via_label);
        put_u32(buf, self.nh_obj_id);
        put_u32(buf, self.nh_classify_table_index);
        put_u8(buf, self.n_labels);
        // label_stack[16]: fib_mpls_label_t
        //   is_uniform(u8) + label(u32) + ttl(u8) + exp(u8) = 7 bytes each
        for i in 0..16usize {
            if i < self.label_stack.len() {
                put_u8(buf, 0); // is_uniform
                put_u32(buf, self.label_stack[i]); // label
                put_u8(buf, 0); // ttl
                put_u8(buf, 0); // exp
            } else {
                // 7 zero bytes
                buf.extend_from_slice(&[0u8; 7]);
            }
        }
    }

    pub fn decode(buf: &[u8], off: &mut usize) -> Result<Self, VppError> {
        let sw_if_index = get_u32(buf, off)?;
        let table_id = get_u32(buf, off)?;
        let rpf_id = get_u32(buf, off)?;
        let weight = get_u8(buf, off)?;
        let preference = get_u8(buf, off)?;
        let path_type = get_u32(buf, off)?;
        let flags = get_u32(buf, off)?;
        let proto = get_u32(buf, off)?;
        let nh_addr = get_array::<16>(buf, off)?;
        let nh_via_label = get_u32(buf, off)?;
        let nh_obj_id = get_u32(buf, off)?;
        let nh_classify_table_index = get_u32(buf, off)?;
        let n_labels = get_u8(buf, off)?;
        let mut label_stack = Vec::new();
        for _ in 0..16u8 {
            // fib_mpls_label_t: is_uniform(u8) + label(u32) + ttl(u8) + exp(u8) = 7 bytes
            let _is_uniform = get_u8(buf, off)?;
            let label = get_u32(buf, off)?;
            let _ttl = get_u8(buf, off)?;
            let _exp = get_u8(buf, off)?;
            if label != 0 {
                label_stack.push(label);
            }
        }

        Ok(FibPath {
            sw_if_index,
            table_id,
            rpf_id,
            weight,
            preference,
            path_type,
            flags,
            proto,
            nh_addr,
            nh_via_label,
            nh_obj_id,
            nh_classify_table_index,
            n_labels,
            label_stack,
        })
    }
}

/// Add or delete an IP route.
#[derive(Debug, Clone)]
pub struct IpRouteAddDel {
    /// true = add, false = delete.
    pub is_add: bool,
    /// true = add/remove path from multipath set.
    pub is_multipath: bool,
    /// Route details.
    pub route: IpRoute,
}

/// An IP route (prefix + paths).
#[derive(Debug, Clone)]
pub struct IpRoute {
    pub table_id: u32,
    pub stats_index: u32,
    pub prefix: Prefix,
    pub n_paths: u8,
    pub paths: Vec<FibPath>,
}

impl VppMessage for IpRouteAddDel {
    const NAME: &'static str = "ip_route_add_del";
    const CRC: &'static str = "b8ecfe0d";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.is_add as u8);
        put_u8(buf, self.is_multipath as u8);
        // ip_route
        put_u32(buf, self.route.table_id);
        put_u32(buf, self.route.stats_index);
        self.route.prefix.encode(buf);
        put_u8(buf, self.route.paths.len() as u8);
        for path in &self.route.paths {
            path.encode(buf);
        }
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("ip_route_add_del is send-only".into()))
    }
}

/// Reply to ip_route_add_del.
#[derive(Debug, Clone)]
pub struct IpRouteAddDelReply {
    pub retval: i32,
    pub stats_index: u32,
}

impl VppMessage for IpRouteAddDelReply {
    const NAME: &'static str = "ip_route_add_del_reply";
    const CRC: &'static str = "1992deab";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        let stats_index = get_u32(buf, &mut off)?;
        Ok(IpRouteAddDelReply {
            retval,
            stats_index,
        })
    }
}

/// Dump IP routes from a FIB table.
#[derive(Debug, Clone)]
pub struct IpRouteDump {
    pub table: IpTable,
}

/// Identifies a FIB table.
#[derive(Debug, Clone)]
pub struct IpTable {
    pub table_id: u32,
    pub is_ip6: bool,
    pub name: String,
}

/// Create or delete a FIB table.
///
/// VPP allows the same table to be added repeatedly (each `is_add=1`
/// is a no-op after the first), but a table only needs to be deleted
/// once. `table_id` 0 is the default VRF and must not be deleted.
#[derive(Debug, Clone)]
pub struct IpTableAddDel {
    /// true = add, false = delete.
    pub is_add: bool,
    /// Table identity. `name` is a free-form label that surfaces in
    /// `show ip fib summary`; it doesn't affect lookup.
    pub table: IpTable,
}

impl VppMessage for IpTableAddDel {
    const NAME: &'static str = "ip_table_add_del";
    const CRC: &'static str = "0ffdaec0";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.is_add as u8);
        // vl_api_ip_table_t: u32 table_id, bool is_ip6, string name[64]
        put_u32(buf, self.table.table_id);
        put_u8(buf, self.table.is_ip6 as u8);
        let name_bytes = self.table.name.as_bytes();
        let len = name_bytes.len().min(63);
        let mut name_buf = [0u8; 64];
        name_buf[..len].copy_from_slice(&name_bytes[..len]);
        put_bytes(buf, &name_buf);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("ip_table_add_del is send-only".into()))
    }
}

/// Reply to ip_table_add_del. Autoreply — only carries retval.
#[derive(Debug, Clone)]
pub struct IpTableAddDelReply {
    pub retval: i32,
}

impl VppMessage for IpTableAddDelReply {
    const NAME: &'static str = "ip_table_add_del_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(IpTableAddDelReply { retval })
    }
}

/// Dump every FIB table currently present in VPP (both v4 and v6).
/// Each table surfaces as one IpTableDetails reply.
#[derive(Debug, Clone)]
pub struct IpTableDump;

impl VppMessage for IpTableDump {
    const NAME: &'static str = "ip_table_dump";
    const CRC: &'static str = "51077d14";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("ip_table_dump is send-only".into()))
    }
}

/// One entry returned by ip_table_dump.
#[derive(Debug, Clone)]
pub struct IpTableDetails {
    pub table: IpTable,
}

impl VppMessage for IpTableDetails {
    const NAME: &'static str = "ip_table_details";
    const CRC: &'static str = "c79fca0f";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let table_id = get_u32(buf, &mut off)?;
        let is_ip6 = get_u8(buf, &mut off)? != 0;
        // name: string[64] — fixed 64-byte NUL-padded
        if buf.len() < off + 64 {
            return Err(VppError::Decode("ip_table_details: short name".into()));
        }
        let name_bytes = &buf[off..off + 64];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(64);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
        Ok(IpTableDetails {
            table: IpTable {
                table_id,
                is_ip6,
                name,
            },
        })
    }
}

impl VppMessage for IpRouteDump {
    const NAME: &'static str = "ip_route_dump";
    const CRC: &'static str = "b9d2e09e";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.table.table_id);
        put_u8(buf, self.table.is_ip6 as u8);
        // name: string[64] — fixed 64-byte NUL-padded
        let name_bytes = self.table.name.as_bytes();
        let len = name_bytes.len().min(63);
        let mut name_buf = [0u8; 64];
        name_buf[..len].copy_from_slice(&name_bytes[..len]);
        put_bytes(buf, &name_buf);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("ip_route_dump is send-only".into()))
    }
}

/// Single route entry returned by ip_route_dump.
#[derive(Debug, Clone)]
pub struct IpRouteDetails {
    pub route: IpRoute,
}

impl VppMessage for IpRouteDetails {
    const NAME: &'static str = "ip_route_details";
    const CRC: &'static str = "bda8f315";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let table_id = get_u32(buf, &mut off)?;
        let stats_index = get_u32(buf, &mut off)?;
        let prefix = Prefix::decode(buf, &mut off)?;
        let n_paths = get_u8(buf, &mut off)?;
        let mut paths = Vec::with_capacity(n_paths as usize);
        for _ in 0..n_paths {
            paths.push(FibPath::decode(buf, &mut off)?);
        }
        Ok(IpRouteDetails {
            route: IpRoute {
                table_id,
                stats_index,
                prefix,
                n_paths,
                paths,
            },
        })
    }
}

/// ip_address_dump — request all addresses on an interface.
///
/// Reply is a stream of ip_address_details followed by control_ping_reply.
#[derive(Debug, Clone)]
pub struct IpAddressDump {
    pub sw_if_index: u32,
    pub is_ipv6: bool,
}

impl VppMessage for IpAddressDump {
    const NAME: &'static str = "ip_address_dump";
    const CRC: &'static str = "2d033de4";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
        put_u8(buf, self.is_ipv6 as u8);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("ip_address_dump is send-only".into()))
    }
}

/// sw_interface_ip6_get_link_local_address — fetch the link-local
/// address for an interface. The link-local is auto-derived by VPP
/// and is NOT returned by ip_address_dump, so callers need this
/// dedicated request.
#[derive(Debug, Clone)]
pub struct SwInterfaceIp6GetLinkLocalAddress {
    pub sw_if_index: u32,
}

impl VppMessage for SwInterfaceIp6GetLinkLocalAddress {
    const NAME: &'static str = "sw_interface_ip6_get_link_local_address";
    const CRC: &'static str = "f9e6675e";
    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
    }
    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode("send-only".into()))
    }
}

#[derive(Debug, Clone)]
pub struct SwInterfaceIp6GetLinkLocalAddressReply {
    pub retval: i32,
    /// 16-byte IPv6 link-local address.
    pub ip: [u8; 16],
}

impl VppMessage for SwInterfaceIp6GetLinkLocalAddressReply {
    const NAME: &'static str = "sw_interface_ip6_get_link_local_address_reply";
    const CRC: &'static str = "d16b7130";
    fn encode_fields(&self, _buf: &mut Vec<u8>) {}
    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = crate::message::get_i32(buf, &mut off)?;
        let ip = get_array::<16>(buf, &mut off)?;
        Ok(SwInterfaceIp6GetLinkLocalAddressReply { retval, ip })
    }
}

/// Single address entry returned by ip_address_dump.
#[derive(Debug, Clone)]
pub struct IpAddressDetails {
    pub sw_if_index: u32,
    pub prefix: Prefix,
}

impl VppMessage for IpAddressDetails {
    const NAME: &'static str = "ip_address_details";
    const CRC: &'static str = "ee29b797";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let sw_if_index = get_u32(buf, &mut off)?;
        let prefix = Prefix::decode(buf, &mut off)?;
        Ok(IpAddressDetails { sw_if_index, prefix })
    }
}

/// Enable or disable IPv6 processing on an interface (drives RA/SLAAC,
/// link-local generation, etc).
///
/// Wire layout (after 10-byte request header):
///   sw_if_index: u32
///   enable: bool (u8)
#[derive(Debug, Clone)]
pub struct SwInterfaceIp6EnableDisable {
    pub sw_if_index: u32,
    pub enable: bool,
}

impl VppMessage for SwInterfaceIp6EnableDisable {
    const NAME: &'static str = "sw_interface_ip6_enable_disable";
    const CRC: &'static str = "ae6cfcfb";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.sw_if_index);
        put_u8(buf, self.enable as u8);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode(
            "sw_interface_ip6_enable_disable is send-only".into(),
        ))
    }
}

/// Reply to sw_interface_ip6_enable_disable.
#[derive(Debug, Clone)]
pub struct SwInterfaceIp6EnableDisableReply {
    pub retval: i32,
}

impl VppMessage for SwInterfaceIp6EnableDisableReply {
    const NAME: &'static str = "sw_interface_ip6_enable_disable_reply";
    const CRC: &'static str = "e8d4e804";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        Ok(SwInterfaceIp6EnableDisableReply { retval })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_ipv4_roundtrip() {
        let prefix = Prefix::ipv4([10, 0, 0, 0], 24);
        let mut buf = Vec::new();
        prefix.encode(&mut buf);

        let mut off = 0;
        let decoded = Prefix::decode(&buf, &mut off).unwrap();
        assert_eq!(decoded.af, AddressFamily::Ipv4);
        assert_eq!(&decoded.address[..4], &[10, 0, 0, 0]);
        assert_eq!(decoded.len, 24);
    }

    #[test]
    fn test_fib_path_via_ipv4() {
        let path = FibPath::via_ipv4([10, 0, 0, 1], 3);
        assert_eq!(&path.nh_addr[..4], &[10, 0, 0, 1]);
        assert_eq!(path.sw_if_index, 3);
        assert_eq!(path.weight, 1);
    }

    #[test]
    fn test_ip_route_add_del_encode() {
        let msg = IpRouteAddDel {
            is_add: true,
            is_multipath: false,
            route: IpRoute {
                table_id: 0,
                stats_index: 0,
                prefix: Prefix::ipv4([192, 168, 1, 0], 24),
                n_paths: 1,
                paths: vec![FibPath::via_ipv4([10, 0, 0, 1], 1)],
            },
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // Should encode without panic; exact length depends on FibPath encoding
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_sw_interface_ip6_enable_disable_encode() {
        let msg = SwInterfaceIp6EnableDisable {
            sw_if_index: 4,
            enable: true,
        };
        let mut buf = Vec::new();
        msg.encode_fields(&mut buf);
        // 4 (sw_if_index) + 1 (enable) = 5
        assert_eq!(buf.len(), 5);
        assert_eq!(&buf[0..4], &4u32.to_be_bytes());
        assert_eq!(buf[4], 1);

        let disable = SwInterfaceIp6EnableDisable {
            sw_if_index: 4,
            enable: false,
        };
        let mut buf = Vec::new();
        disable.encode_fields(&mut buf);
        assert_eq!(buf[4], 0);
    }

    #[test]
    fn test_sw_interface_ip6_enable_disable_reply_decode() {
        let buf = 0i32.to_be_bytes();
        let r = SwInterfaceIp6EnableDisableReply::decode_fields(&buf).unwrap();
        assert_eq!(r.retval, 0);
    }
}
