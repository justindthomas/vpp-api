//! DHCP punt-socket probe — the Phase 0 gating spike for `imp-dhcpd`.
//!
//! Answers three questions for VPP 25.10:
//!
//!   Q1. Does `PuntType::L4` registered for UDP/67 receive broadcast
//!       `255.255.255.255:68 → 255.255.255.255:67` DISCOVER packets
//!       when the client has no lease yet?
//!
//!   Q2. Does the same registration also deliver *unicast* renewal
//!       packets (`client_ip:68 → server_ip:67`) to the punt socket?
//!
//!   Q3. Can we inject a broadcast DHCP OFFER via `PUNT_L2` using
//!       destination MAC `ff:ff:ff:ff:ff:ff` and have a real client
//!       (dhcpcd) accept it?
//!
//! The probe is read-only by default; set `DHCP_PROBE_RESPOND=1` to
//! craft + inject an OFFER in response to the first DISCOVER seen.
//!
//! Run inside the dataplane namespace on a VM where VPP is up, no
//! other DHCP server is listening, and a peer client is ready to
//! send DISCOVERs:
//!
//!   systemctl stop isc-dhcp-server  # or whatever else binds 67
//!   # Make sure VPP's own dhcp client plugin is not configured for
//!   # the serving interface — it'll race the punt registration.
//!   vppctl -s /run/vpp/core-cli.sock show dhcp client
//!
//!   ip netns exec dataplane ./dhcp_punt_probe /run/vpp/core-api.sock
//!
//!   # On the peer, kick dhcpcd so it sends a DISCOVER:
//!   dhcpcd -T eth1  # test mode — does a full handshake
//!
//! On exit (Ctrl-C or 60s timeout), issues a deregister so VPP's
//! punt_client_db is clean for the next run.

use std::os::unix::net::UnixDatagram;
use std::time::{Duration, Instant};

use vpp_api::generated::interface::{SwInterfaceDetails, SwInterfaceDump};
use vpp_api::generated::ip::{IpAddressDetails, IpAddressDump};
use vpp_api::generated::punt::{
    PuntSocketDeregister, PuntSocketDeregisterReply, PuntSocketRegister,
    PuntSocketRegisterReply, PuntType,
};
use vpp_api::VppClient;

const IP_PROTO_UDP: u8 = 17;
const AF_IPV4: u8 = 0;
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const CLIENT_SOCKET: &str = "/tmp/dhcp-punt-probe.sock";

/// Match values from punt.h:
///   PUNT_L2         = 0  (next: interface-output, expects L2 frame)
///   PUNT_IP4_ROUTED = 1  (next: ip4-lookup,       expects IP packet)
const PUNT_ACTION_L2: u32 = 0;
#[allow(dead_code)]
const PUNT_ACTION_IP4_ROUTED: u32 = 1;

/// BOOTP magic cookie (RFC 951 + RFC 2131) — marks the options area.
const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

// DHCP option codes (RFC 2132)
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_CLIENT_ID: u8 = 61;
const OPT_END: u8 = 255;

// DHCP message types (RFC 2132 §9.6)
const DHCPDISCOVER: u8 = 1;
const DHCPOFFER: u8 = 2;
const DHCPREQUEST: u8 = 3;
const DHCPDECLINE: u8 = 4;
const DHCPACK: u8 = 5;
const DHCPNAK: u8 = 6;
const DHCPRELEASE: u8 = 7;
const DHCPINFORM: u8 = 8;

fn msg_type_name(t: u8) -> &'static str {
    match t {
        DHCPDISCOVER => "DISCOVER",
        DHCPOFFER => "OFFER",
        DHCPREQUEST => "REQUEST",
        DHCPDECLINE => "DECLINE",
        DHCPACK => "ACK",
        DHCPNAK => "NAK",
        DHCPRELEASE => "RELEASE",
        DHCPINFORM => "INFORM",
        _ => "?",
    }
}

/// Compute IPv4 16-bit ones-complement checksum over `data`.
fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | data[i + 1] as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// UDP checksum with IPv4 pseudo-header (RFC 768 / 1071).
fn udp_checksum(src: [u8; 4], dst: [u8; 4], udp_with_zero_cksum: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp_with_zero_cksum.len());
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.push(0); // zero
    pseudo.push(IP_PROTO_UDP);
    pseudo.extend_from_slice(&(udp_with_zero_cksum.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp_with_zero_cksum);
    // Pad to even length
    if pseudo.len() % 2 != 0 {
        pseudo.push(0);
    }
    let ck = ip_checksum(&pseudo);
    if ck == 0 {
        // UDP spec: a checksum of 0 means "no checksum" — use 0xffff
        // (all-ones) instead, which is numerically equivalent in
        // ones-complement arithmetic.
        0xffff
    } else {
        ck
    }
}

/// Parse a DISCOVER/REQUEST body out of a received UDP datagram.
/// Returns (xid, chaddr[0..6], client_id_opt_bytes, requested_msg_type).
#[derive(Debug, Clone)]
struct DhcpParse {
    xid: u32,
    flags: u16,
    chaddr6: [u8; 6],
    msg_type: u8,
    #[allow(dead_code)]
    client_id: Option<Vec<u8>>,
    broadcast_flag_set: bool,
}

fn parse_dhcp(payload: &[u8]) -> Option<DhcpParse> {
    if payload.len() < 240 {
        return None;
    }
    let xid = u32::from_be_bytes(payload[4..8].try_into().ok()?);
    let flags = u16::from_be_bytes(payload[10..12].try_into().ok()?);
    let mut chaddr6 = [0u8; 6];
    chaddr6.copy_from_slice(&payload[28..34]);
    if payload[236..240] != DHCP_MAGIC_COOKIE {
        return None;
    }
    let mut msg_type = 0u8;
    let mut client_id: Option<Vec<u8>> = None;
    let mut i = 240;
    while i < payload.len() {
        let code = payload[i];
        if code == OPT_END {
            break;
        }
        if code == 0 {
            // pad
            i += 1;
            continue;
        }
        if i + 1 >= payload.len() {
            break;
        }
        let len = payload[i + 1] as usize;
        if i + 2 + len > payload.len() {
            break;
        }
        let body = &payload[i + 2..i + 2 + len];
        match code {
            OPT_MSG_TYPE => {
                if !body.is_empty() {
                    msg_type = body[0];
                }
            }
            OPT_CLIENT_ID => {
                client_id = Some(body.to_vec());
            }
            _ => {}
        }
        i += 2 + len;
    }
    Some(DhcpParse {
        xid,
        flags,
        chaddr6,
        msg_type,
        client_id,
        broadcast_flag_set: (flags & 0x8000) != 0,
    })
}

/// Build a minimal BOOTP/DHCP reply body (308 bytes fixed + trailing
/// options + END). `op=2` (BOOTREPLY). Broadcast flag is echoed from
/// the incoming request.
fn build_dhcp_offer(
    xid: u32,
    flags: u16,
    yiaddr: [u8; 4],
    siaddr: [u8; 4],
    chaddr6: [u8; 6],
    server_id: [u8; 4],
    subnet_mask: [u8; 4],
    router: [u8; 4],
    dns: [u8; 4],
    lease_time_secs: u32,
    msg_type: u8,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(512);
    b.push(2); // op = BOOTREPLY
    b.push(1); // htype = ethernet
    b.push(6); // hlen
    b.push(0); // hops
    b.extend_from_slice(&xid.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes()); // secs
    b.extend_from_slice(&flags.to_be_bytes()); // echo broadcast flag
    b.extend_from_slice(&[0, 0, 0, 0]); // ciaddr
    b.extend_from_slice(&yiaddr); // yiaddr
    b.extend_from_slice(&siaddr); // siaddr (next server)
    b.extend_from_slice(&[0, 0, 0, 0]); // giaddr
    // chaddr[16]
    b.extend_from_slice(&chaddr6);
    b.extend_from_slice(&[0u8; 10]);
    // sname[64] + file[128]
    b.extend_from_slice(&[0u8; 64]);
    b.extend_from_slice(&[0u8; 128]);
    // magic cookie
    b.extend_from_slice(&DHCP_MAGIC_COOKIE);

    // Options
    b.push(OPT_MSG_TYPE);
    b.push(1);
    b.push(msg_type);

    b.push(OPT_SERVER_ID);
    b.push(4);
    b.extend_from_slice(&server_id);

    b.push(OPT_LEASE_TIME);
    b.push(4);
    b.extend_from_slice(&lease_time_secs.to_be_bytes());

    b.push(OPT_SUBNET_MASK);
    b.push(4);
    b.extend_from_slice(&subnet_mask);

    b.push(OPT_ROUTER);
    b.push(4);
    b.extend_from_slice(&router);

    b.push(OPT_DNS);
    b.push(4);
    b.extend_from_slice(&dns);

    b.push(OPT_END);

    // Pad to minimum BOOTP packet size (300 bytes) — some clients are
    // picky about short replies.
    while b.len() < 300 {
        b.push(0);
    }
    b
}

/// Wrap a DHCP body in UDP, IP, and ethernet headers. Returns a full
/// L2 frame suitable for `PUNT_L2` injection.
fn build_l2_dhcp_reply(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    dhcp_payload: &[u8],
) -> Vec<u8> {
    // UDP header (8) + payload, checksum placeholder zero.
    let udp_len: u16 = 8 + dhcp_payload.len() as u16;
    let mut udp = Vec::with_capacity(udp_len as usize);
    udp.extend_from_slice(&DHCP_SERVER_PORT.to_be_bytes()); // sport = 67
    udp.extend_from_slice(&DHCP_CLIENT_PORT.to_be_bytes()); // dport = 68
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum placeholder
    udp.extend_from_slice(dhcp_payload);
    let ck = udp_checksum(src_ip, dst_ip, &udp);
    udp[6..8].copy_from_slice(&ck.to_be_bytes());

    // IP header
    let total_length: u16 = 20 + udp.len() as u16;
    let mut ip = Vec::with_capacity(total_length as usize);
    ip.push(0x45);
    ip.push(0x10); // tos (sometimes 0x10 for low-latency; either fine)
    ip.extend_from_slice(&total_length.to_be_bytes());
    ip.extend_from_slice(&[0, 0]); // id
    ip.extend_from_slice(&[0x40, 0]); // DF flag + frag off = 0
    ip.push(64); // ttl
    ip.push(IP_PROTO_UDP);
    ip.extend_from_slice(&[0, 0]); // cksum placeholder
    ip.extend_from_slice(&src_ip);
    ip.extend_from_slice(&dst_ip);
    let ck = ip_checksum(&ip);
    ip[10..12].copy_from_slice(&ck.to_be_bytes());
    ip.extend_from_slice(&udp);

    // Ethernet header
    let mut frame = Vec::with_capacity(14 + ip.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let vpp_socket_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/run/vpp/core-api.sock".to_string());

    // Step 1: bind client UNIX datagram socket that VPP will write to.
    let _ = std::fs::remove_file(CLIENT_SOCKET);
    let rx = UnixDatagram::bind(CLIENT_SOCKET)?;
    std::fs::set_permissions(
        CLIENT_SOCKET,
        std::os::unix::fs::PermissionsExt::from_mode(0o777),
    )?;
    println!("[+] bound client socket at {}", CLIENT_SOCKET);

    // Step 2: connect to VPP binary API and register UDP/67 punt.
    println!("[+] connecting to VPP at {}...", vpp_socket_path);
    let client = VppClient::connect(&vpp_socket_path).await?;
    println!("[+] connected, client_index={}", client.client_index());

    let register = PuntSocketRegister {
        header_version: 1,
        punt_type: PuntType::L4,
        af: AF_IPV4,
        protocol: IP_PROTO_UDP,
        port: DHCP_SERVER_PORT,
        pathname: CLIENT_SOCKET.to_string(),
    };
    println!(
        "[+] sending punt_socket_register: type=L4 af=IP4 proto=UDP port={}",
        DHCP_SERVER_PORT
    );
    let reply: PuntSocketRegisterReply = client
        .request::<PuntSocketRegister, PuntSocketRegisterReply>(register)
        .await?;
    if reply.retval != 0 {
        eprintln!("[!] register failed: retval={}", reply.retval);
        return Ok(());
    }
    let vpp_server_path = reply.pathname.trim_end_matches('\0').to_string();
    println!("[+] registered. VPP TX pathname = {:?}", vpp_server_path);

    // Step 3: look up interfaces so we can respond with the right
    // sw_if_index + MAC. The operator picks which iface to serve on
    // via DHCP_PROBE_IFACE (default: first LAN-ish name we find).
    let ifaces: Vec<SwInterfaceDetails> = client
        .dump::<SwInterfaceDump, SwInterfaceDetails>(SwInterfaceDump::default())
        .await?;
    let iface_arg = std::env::var("DHCP_PROBE_IFACE").ok();
    let serve_iface = match iface_arg {
        Some(name) => ifaces
            .iter()
            .find(|i| i.interface_name.trim_end_matches('\0') == name)
            .cloned(),
        None => ifaces
            .iter()
            .find(|i| {
                let n = i.interface_name.trim_end_matches('\0');
                n == "lan" || n == "internal" || n == "wan"
            })
            .cloned(),
    };
    if let Some(iface) = serve_iface.as_ref() {
        println!(
            "[+] serving interface = {} (sw_if_index={}, up={}, mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
            iface.interface_name.trim_end_matches('\0'),
            iface.sw_if_index,
            iface.flags.is_admin_up(),
            iface.l2_address[0],
            iface.l2_address[1],
            iface.l2_address[2],
            iface.l2_address[3],
            iface.l2_address[4],
            iface.l2_address[5],
        );
    } else {
        println!("[!] no serving interface found — RX-only mode");
    }

    // Discover server IP on that interface.
    let server_ip: Option<[u8; 4]> = if let Some(iface) = serve_iface.as_ref() {
        let addrs: Vec<IpAddressDetails> = client
            .dump::<IpAddressDump, IpAddressDetails>(IpAddressDump {
                sw_if_index: iface.sw_if_index,
                is_ipv6: false,
            })
            .await?;
        addrs.first().and_then(|a| {
            if a.prefix.af == vpp_api::generated::ip::AddressFamily::Ipv4 {
                let mut v4 = [0u8; 4];
                v4.copy_from_slice(&a.prefix.address[..4]);
                Some(v4)
            } else {
                None
            }
        })
    } else {
        None
    };

    let server_ip = server_ip.or_else(|| {
        std::env::var("DHCP_PROBE_SERVER_IP").ok().and_then(|s| {
            let parts: Vec<&str> = s.split('.').collect();
            if parts.len() == 4 {
                let mut v = [0u8; 4];
                for (i, p) in parts.iter().enumerate() {
                    v[i] = p.parse().ok()?;
                }
                Some(v)
            } else {
                None
            }
        })
    });
    if let Some(ip) = server_ip {
        println!(
            "[+] server IP = {}.{}.{}.{}",
            ip[0], ip[1], ip[2], ip[3]
        );
    } else {
        println!("[!] no server IP discovered — OFFER injection disabled");
    }

    let respond = std::env::var("DHCP_PROBE_RESPOND").ok().as_deref() == Some("1");
    if respond {
        println!("[+] DHCP_PROBE_RESPOND=1 — will inject OFFER on first DISCOVER");
    }
    let offer_ip: [u8; 4] = std::env::var("DHCP_PROBE_OFFER_IP")
        .ok()
        .and_then(|s| {
            let parts: Vec<&str> = s.split('.').collect();
            if parts.len() == 4 {
                let mut v = [0u8; 4];
                for (i, p) in parts.iter().enumerate() {
                    v[i] = p.parse().ok()?;
                }
                Some(v)
            } else {
                None
            }
        })
        .unwrap_or([10, 99, 99, 99]);

    // TX socket for injection
    let tx = UnixDatagram::unbound()?;

    // Step 4: read datagrams with a 60-second overall timeout.
    rx.set_nonblocking(true)?;
    let rx = tokio::net::UnixDatagram::from_std(rx)?;

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut packet_count = 0;
    let mut offer_sent = false;
    let mut buf = vec![0u8; 65536];
    println!("\n[+] listening for DHCP traffic on UDP/67 (60s)...\n");

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let recv = tokio::time::timeout(remaining, rx.recv(&mut buf)).await;
        let n = match recv {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                eprintln!("[!] recv error: {}", e);
                break;
            }
            Err(_) => break, // timeout
        };
        packet_count += 1;

        if n < 8 {
            println!("  short datagram: {} bytes", n);
            continue;
        }

        let sw_if_index = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let action = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let payload = &buf[8..n];

        println!(
            "[#{}] {} bytes  sw_if_index={} action={}  payload={} bytes",
            packet_count, n, sw_if_index, action, payload.len()
        );

        if payload.len() < 14 {
            continue;
        }
        let ethertype = u16::from_be_bytes([payload[12], payload[13]]);
        let dst_mac_str = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5]
        );
        let src_mac_str = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            payload[6], payload[7], payload[8], payload[9], payload[10], payload[11]
        );
        println!(
            "    L2: dst={} src={} ethertype=0x{:04x}",
            dst_mac_str, src_mac_str, ethertype
        );

        if ethertype != 0x0800 || payload.len() < 14 + 20 + 8 {
            continue;
        }
        let ip = &payload[14..];
        let version_ihl = ip[0];
        let ihl = ((version_ihl & 0x0f) as usize) * 4;
        let proto = ip[9];
        let src_ip = [ip[12], ip[13], ip[14], ip[15]];
        let dst_ip = [ip[16], ip[17], ip[18], ip[19]];
        println!(
            "    L3: ver=0x{:x} ihl={} proto={} {}.{}.{}.{} -> {}.{}.{}.{}",
            version_ihl,
            ihl,
            proto,
            src_ip[0],
            src_ip[1],
            src_ip[2],
            src_ip[3],
            dst_ip[0],
            dst_ip[1],
            dst_ip[2],
            dst_ip[3],
        );

        if proto != IP_PROTO_UDP {
            continue;
        }
        let udp = &ip[ihl..];
        if udp.len() < 8 {
            continue;
        }
        let sport = u16::from_be_bytes([udp[0], udp[1]]);
        let dport = u16::from_be_bytes([udp[2], udp[3]]);
        let dhcp = &udp[8..];
        println!("    L4: UDP {} -> {}  dhcp_bytes={}", sport, dport, dhcp.len());

        let is_broadcast = dst_ip == [255, 255, 255, 255];
        let is_unicast = !is_broadcast && dst_ip != [0, 0, 0, 0];
        println!(
            "    Q1(broadcast-rx)={} Q2(unicast-rx)={}",
            is_broadcast, is_unicast
        );

        let parsed = match parse_dhcp(dhcp) {
            Some(p) => p,
            None => {
                println!("    !! not a valid DHCP packet (cookie mismatch?)");
                continue;
            }
        };
        println!(
            "    DHCP: {} xid=0x{:08x} chaddr={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} bflag={}",
            msg_type_name(parsed.msg_type),
            parsed.xid,
            parsed.chaddr6[0],
            parsed.chaddr6[1],
            parsed.chaddr6[2],
            parsed.chaddr6[3],
            parsed.chaddr6[4],
            parsed.chaddr6[5],
            parsed.broadcast_flag_set,
        );

        // Q3: inject an OFFER in response to the first DISCOVER we see.
        if respond
            && !offer_sent
            && parsed.msg_type == DHCPDISCOVER
            && serve_iface.is_some()
            && server_ip.is_some()
        {
            let iface = serve_iface.as_ref().unwrap();
            let sid = server_ip.unwrap();
            let dhcp_body = build_dhcp_offer(
                parsed.xid,
                parsed.flags, // echo broadcast flag
                offer_ip,
                sid,
                parsed.chaddr6,
                sid,
                [255, 255, 255, 0],
                sid, // router = self
                sid, // DNS = self
                3600,
                DHCPOFFER,
            );
            let mut src_mac = [0u8; 6];
            src_mac.copy_from_slice(&iface.l2_address[..6]);
            let dst_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
            let frame = build_l2_dhcp_reply(
                src_mac,
                dst_mac,
                sid,
                [255, 255, 255, 255],
                &dhcp_body,
            );
            let mut dgram = Vec::with_capacity(8 + frame.len());
            dgram.extend_from_slice(&iface.sw_if_index.to_le_bytes());
            dgram.extend_from_slice(&PUNT_ACTION_L2.to_le_bytes());
            dgram.extend_from_slice(&frame);
            match tx.send_to(&dgram, &vpp_server_path) {
                Ok(n) => {
                    println!(
                        "[TX] Q3 injecting OFFER: {} bytes on sw_if_index={} via PUNT_L2 bcast",
                        n, iface.sw_if_index
                    );
                    offer_sent = true;
                }
                Err(e) => println!("[TX] OFFER send_to error: {}", e),
            }
        }
        println!();
    }

    println!("[+] deregistering...");
    let dreply: PuntSocketDeregisterReply = client
        .request::<PuntSocketDeregister, PuntSocketDeregisterReply>(PuntSocketDeregister {
            punt_type: PuntType::L4,
            af: AF_IPV4,
            protocol: IP_PROTO_UDP,
            port: DHCP_SERVER_PORT,
        })
        .await?;
    println!("[+] deregister retval={}", dreply.retval);

    let _ = std::fs::remove_file(CLIENT_SOCKET);
    println!(
        "\n[+] done. captured {} packets, offer_sent={}",
        packet_count, offer_sent
    );
    Ok(())
}
