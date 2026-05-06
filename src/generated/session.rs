//! VPP session-layer API messages.
//!
//! Currently exposes only `app_namespace_add_del_v4` — the
//! single message impd needs to register per-VRF VPP session-layer
//! namespaces. App namespaces pin an "app" (any process attaching
//! via VCL) to specific IPv4 / IPv6 FIB tables, so per-VRF bgpd /
//! dnsd children land their TCP/UDP sockets in the right table.
//!
//! Hand-written rather than codegen-derived because we don't yet
//! have `session.api.json` in api-json/. CRC and field layout
//! verified against VPP 25.10 source via local vppapigen run.

use crate::error::VppError;
use crate::message::*;

/// Add or delete a VPP session-layer application namespace.
///
/// `is_add=true` creates the namespace. `is_add=false` deletes it.
/// VPP session lookup tables key by `(fib_index, namespace_index)`,
/// so once registered, any process that attaches with
/// `namespace-id <name>` (set via `vcl.conf` or
/// `VPPCOM_ENV_APP_NAMESPACE_ID`) has its sockets routed through the
/// FIB tables specified here.
///
/// `sw_if_index` lets you anchor the namespace to a specific
/// interface; `~0` (the default) means "no preference, use FIB ids
/// directly". When `sw_if_index != ~0`, VPP overrides
/// `ip4_fib_id` / `ip6_fib_id` with the interface's tables.
///
/// `sock_name` is the path of the per-namespace app-socket-api
/// socket VPP creates (`/run/vpp/app_ns_sockets/<sock_name>` by
/// default). Empty means "use the namespace_id as the socket name"
/// — that's what we want.
#[derive(Debug, Clone)]
pub struct AppNamespaceAddDelV4 {
    /// 0 = no shared secret. We don't authenticate per-namespace
    /// attaches; the app-socket-api file's UNIX permissions are
    /// the access control.
    pub secret: u64,
    /// true = add, false = delete.
    pub is_add: bool,
    /// `~0` (= u32::MAX) for FIB-only scoping. When set, VPP uses
    /// the interface's FIB tables and ignores ip4_fib_id /
    /// ip6_fib_id.
    pub sw_if_index: u32,
    /// IPv4 FIB table-id this namespace pins to. `0` is the
    /// default VRF.
    pub ip4_fib_id: u32,
    /// IPv6 FIB table-id (independent of v4). `0` is the default
    /// VRF.
    pub ip6_fib_id: u32,
    /// Operator-facing namespace name. Truncated to 63 bytes (the
    /// last byte is the NUL terminator). VCL-side
    /// `namespace-id <name>` must match.
    pub namespace_id: String,
    /// Per-namespace app-socket-api socket name. Empty = use
    /// `namespace_id` as the name (which produces
    /// `/run/vpp/app_ns_sockets/<namespace_id>`). impd passes
    /// empty so the socket path matches the per-VRF vcl.conf
    /// rendered at apply time.
    pub sock_name: String,
}

impl VppMessage for AppNamespaceAddDelV4 {
    const NAME: &'static str = "app_namespace_add_del_v4";
    const CRC: &'static str = "42c1d824";

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        put_u64(buf, self.secret);
        put_u8(buf, self.is_add as u8);
        put_u32(buf, self.sw_if_index);
        put_u32(buf, self.ip4_fib_id);
        put_u32(buf, self.ip6_fib_id);
        // namespace_id: string[64] — fixed 64-byte NUL-padded
        let ns_bytes = self.namespace_id.as_bytes();
        let len = ns_bytes.len().min(63);
        let mut ns_buf = [0u8; 64];
        ns_buf[..len].copy_from_slice(&ns_bytes[..len]);
        put_bytes(buf, &ns_buf);
        // sock_name: string[0] — variable-length, prefixed by u32
        // length per VPP wire format.
        let sn = self.sock_name.as_bytes();
        put_u32(buf, sn.len() as u32);
        put_bytes(buf, sn);
    }

    fn decode_fields(_buf: &[u8]) -> Result<Self, VppError> {
        Err(VppError::Decode(
            "app_namespace_add_del_v4 is send-only".into(),
        ))
    }
}

/// Reply to `app_namespace_add_del_v4`. Returns the
/// `appns_index` VPP allocated; we don't track it (VCL apps
/// look up by name, not by index) but capture it for tracing.
#[derive(Debug, Clone)]
pub struct AppNamespaceAddDelV4Reply {
    pub retval: i32,
    pub appns_index: u32,
}

impl VppMessage for AppNamespaceAddDelV4Reply {
    const NAME: &'static str = "app_namespace_add_del_v4_reply";
    const CRC: &'static str = "85137120";

    fn encode_fields(&self, _buf: &mut Vec<u8>) {}

    fn decode_fields(buf: &[u8]) -> Result<Self, VppError> {
        let mut off = 0;
        let retval = get_i32(buf, &mut off)?;
        let appns_index = get_u32(buf, &mut off)?;
        Ok(AppNamespaceAddDelV4Reply {
            retval,
            appns_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_request_with_expected_layout() {
        // Mirror VPP 25.10 wire layout: secret(u64) is_add(u8)
        // sw_if_index(u32) ip4_fib_id(u32) ip6_fib_id(u32)
        // namespace_id(string[64], NUL-padded) sock_name(string[]).
        let req = AppNamespaceAddDelV4 {
            secret: 0,
            is_add: true,
            sw_if_index: u32::MAX,
            ip4_fib_id: 100,
            ip6_fib_id: 200,
            namespace_id: "cust-a".into(),
            sock_name: String::new(),
        };
        let mut buf = Vec::new();
        req.encode_fields(&mut buf);

        // 8 (secret) + 1 (is_add) + 4 (sw_if_index) + 4 (ip4) +
        // 4 (ip6) + 64 (namespace_id) + 4 (sock_name length) = 89.
        assert_eq!(buf.len(), 89);
        // secret = 0
        assert_eq!(&buf[0..8], &[0u8; 8]);
        // is_add = 1
        assert_eq!(buf[8], 1);
        // sw_if_index = 0xffffffff
        assert_eq!(&buf[9..13], &0xffff_ffffu32.to_be_bytes());
        // ip4_fib_id = 100
        assert_eq!(&buf[13..17], &100u32.to_be_bytes());
        // ip6_fib_id = 200
        assert_eq!(&buf[17..21], &200u32.to_be_bytes());
        // namespace_id field is 64 bytes, NUL-padded.
        assert_eq!(&buf[21..27], b"cust-a");
        for &b in &buf[27..85] {
            assert_eq!(b, 0, "namespace_id padding");
        }
        // sock_name length = 0
        assert_eq!(&buf[85..89], &0u32.to_be_bytes());
    }

    #[test]
    fn decodes_reply() {
        // retval=0, appns_index=7 (big-endian wire format).
        let mut buf = Vec::new();
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&7u32.to_be_bytes());
        let r = AppNamespaceAddDelV4Reply::decode_fields(&buf).unwrap();
        assert_eq!(r.retval, 0);
        assert_eq!(r.appns_index, 7);
    }

    #[test]
    fn truncates_long_namespace_id() {
        let req = AppNamespaceAddDelV4 {
            secret: 0,
            is_add: true,
            sw_if_index: u32::MAX,
            ip4_fib_id: 0,
            ip6_fib_id: 0,
            // 70 bytes — VPP allots only 63 (1 byte for NUL).
            namespace_id: "a".repeat(70),
            sock_name: String::new(),
        };
        let mut buf = Vec::new();
        req.encode_fields(&mut buf);
        // Field 5 (namespace_id) starts at offset 21.
        assert_eq!(buf[21..21 + 63].iter().filter(|&&b| b == b'a').count(), 63);
        // The 64th byte must be a NUL terminator.
        assert_eq!(buf[21 + 63], 0);
    }
}
