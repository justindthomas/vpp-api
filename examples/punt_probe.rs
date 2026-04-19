//! Punt-socket probe — registers a punt for IPv4 proto 89 (OSPF),
//! captures the datagram framing, prints what arrives.
//!
//! Run inside the dataplane namespace on a system where VPP is forwarding
//! OSPF traffic and no other process is listening on proto 89:
//!
//!   systemctl stop imp-ospfd
//!   cd ~/imp && cargo run --example punt_probe -- /run/vpp/core-api.sock
//!
//! Goals:
//!   1. Confirm PUNT_TYPE_IP_PROTO register succeeds against VPP 25.10.
//!   2. Capture + print the punt_packetdesc_t header format and
//!      verify it matches our expectations (sw_if_index, action, then
//!      L2+L3 bytes).
//!   3. Decode a few received OSPF frames to confirm we see both
//!      multicast (224.0.0.5) and unicast (NBMA) packets on the same
//!      socket.
//!
//! On exit (Ctrl-C or 60s timeout), issues a deregister so VPP's
//! punt_client_db is clean for the next run.

use std::os::unix::net::UnixDatagram;
use std::time::{Duration, Instant};

use vpp_api::generated::interface::{SwInterfaceDetails, SwInterfaceDump};
use vpp_api::generated::punt::{
    PuntSocketDeregister, PuntSocketDeregisterReply, PuntSocketRegister,
    PuntSocketRegisterReply, PuntType,
};
use vpp_api::VppClient;

const IP_PROTO_OSPF: u8 = 89;
const AF_IPV4: u8 = 0;
const CLIENT_SOCKET: &str = "/tmp/punt-probe.sock";

/// Match values from punt.h:
///   PUNT_L2         = 0  (next: interface-output, expects L2 frame)
///   PUNT_IP4_ROUTED = 1  (next: ip4-lookup,       expects IP packet)
///   PUNT_IP6_ROUTED = 2  (next: ip6-lookup)
const PUNT_ACTION_L2: u32 = 0;
const PUNT_ACTION_IP4_ROUTED: u32 = 1;
#[allow(dead_code)]
const PUNT_ACTION_IP6_ROUTED: u32 = 2; // kept for completeness; v6 probe TBD

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

/// Build a minimal valid OSPFv2 Hello packet and wrap it in an IPv4 header.
/// Returns the full 64-byte IP+OSPF datagram (NO ethernet header).
fn build_test_ospf_hello(src: [u8; 4], dst: [u8; 4], router_id: [u8; 4]) -> Vec<u8> {
    // OSPF Hello body (20 bytes):
    //   network_mask (4) = 255.255.255.0 (decorative for this probe)
    //   hello_interval (2)
    //   options (1), router_priority (1)
    //   router_dead_interval (4)
    //   designated_router (4) = 0
    //   backup_designated_router (4) = 0
    let mut hello_body = Vec::with_capacity(20);
    hello_body.extend_from_slice(&[255, 255, 255, 0]); // mask
    hello_body.extend_from_slice(&10u16.to_be_bytes()); // hello_interval
    hello_body.push(0x02); // options: E-bit (external routing)
    hello_body.push(1); // router priority
    hello_body.extend_from_slice(&40u32.to_be_bytes()); // dead_interval
    hello_body.extend_from_slice(&[0, 0, 0, 0]); // DR
    hello_body.extend_from_slice(&[0, 0, 0, 0]); // BDR

    // OSPF header (24 bytes):
    //   version=2, type=1 Hello, length, router_id, area_id=0,
    //   checksum (computed over header+body, auth_data zeroed), auth_type=0, auth_data=0
    let ospf_length: u16 = 24 + hello_body.len() as u16;
    let mut ospf = Vec::with_capacity(ospf_length as usize);
    ospf.push(2); // version
    ospf.push(1); // type=Hello
    ospf.extend_from_slice(&ospf_length.to_be_bytes());
    ospf.extend_from_slice(&router_id);
    ospf.extend_from_slice(&[0, 0, 0, 0]); // area 0
    ospf.extend_from_slice(&[0, 0]); // checksum placeholder
    ospf.extend_from_slice(&[0, 0]); // auth_type = 0 (null)
    ospf.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // auth_data (excluded from checksum)
    ospf.extend_from_slice(&hello_body);

    // Compute OSPF checksum: IP-style 16-bit ones-complement sum over
    // the OSPF header and body, but with the 8-byte auth_data zeroed
    // AND the checksum field zeroed. Our layout above already has
    // both fields zeroed, so we just checksum the whole thing.
    // But wait — ospf checksum excludes auth_data entirely (bytes 16..24).
    // We need to split into [0..16] + [24..end] for the hash.
    let mut for_cksum = Vec::with_capacity(ospf.len() - 8);
    for_cksum.extend_from_slice(&ospf[0..16]);
    for_cksum.extend_from_slice(&ospf[24..]);
    let ck = ip_checksum(&for_cksum);
    ospf[12..14].copy_from_slice(&ck.to_be_bytes());

    // IP header (20 bytes):
    let total_length: u16 = 20 + ospf.len() as u16;
    let mut ip = Vec::with_capacity(total_length as usize);
    ip.push(0x45); // v4, ihl=5
    ip.push(0x00); // tos=0 (RFC 2328 says 0xc0 for IP Precedence Internet Control, but 0 works)
    ip.extend_from_slice(&total_length.to_be_bytes());
    ip.extend_from_slice(&[0, 0]); // id
    ip.extend_from_slice(&[0, 0]); // flags + frag offset
    ip.push(1); // ttl=1 for OSPF
    ip.push(89); // proto OSPF
    ip.extend_from_slice(&[0, 0]); // checksum placeholder
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let ck = ip_checksum(&ip);
    ip[10..12].copy_from_slice(&ck.to_be_bytes());
    ip.extend_from_slice(&ospf);

    ip
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

    // Step 2: connect to VPP binary API and register.
    println!("[+] connecting to VPP at {}...", vpp_socket_path);
    let client = VppClient::connect(&vpp_socket_path).await?;
    println!("[+] connected, client_index={}", client.client_index());

    let register = PuntSocketRegister {
        header_version: 1,
        punt_type: PuntType::IpProto,
        af: AF_IPV4,
        protocol: IP_PROTO_OSPF,
        port: 0,
        pathname: CLIENT_SOCKET.to_string(),
    };
    println!(
        "[+] sending punt_socket_register: type=IP_PROTO af=IP4 proto={}",
        IP_PROTO_OSPF
    );
    let reply: PuntSocketRegisterReply = client
        .request::<PuntSocketRegister, PuntSocketRegisterReply>(register)
        .await?;
    if reply.retval != 0 {
        eprintln!("[!] register failed: retval={}", reply.retval);
        return Ok(());
    }
    println!(
        "[+] registered. VPP TX pathname = {:?}",
        reply.pathname
    );
    println!("[+] (that's the socket we'd write to for TX injection)");

    // Step 2.5 (optional): inject a test OSPF Hello via the TX socket
    // and confirm it egresses. We do this only when the env var
    // PUNT_PROBE_INJECT=1 is set so the RX-only use case stays pure.
    //
    // Injection path: write to VPP's server socket with a
    // punt_packetdesc_t prefix (action=PUNT_IP4_ROUTED, sw_if_index=wan)
    // followed by the full IP packet. The descriptor tells VPP's
    // punt_socket_rx_node to enqueue into ip4-lookup, which for a
    // 224.0.0.5 destination hits the mfib entry we already have, which
    // both replicates out the phy (Forward) AND loops a copy back via
    // dpo-receive → ip4-local → punt (because the same mfib entry has
    // `via local Forward`). So if both directions work, we should see
    // our own packet echoed back in the recv loop below.
    if std::env::var("PUNT_PROBE_INJECT").ok().as_deref() == Some("1") {
        println!("[+] PUNT_PROBE_INJECT=1 set — preparing TX test");

        // Find the sw_if_index for "wan" so we know where to inject.
        let ifaces: Vec<SwInterfaceDetails> = client
            .dump::<SwInterfaceDump, SwInterfaceDetails>(SwInterfaceDump::default())
            .await?;
        let wan = ifaces
            .iter()
            .find(|i| i.interface_name.trim_end_matches('\0') == "wan")
            .ok_or("could not find interface 'wan'")?;
        println!(
            "[+] wan: sw_if_index={}, admin_up={}",
            wan.sw_if_index,
            wan.flags.is_admin_up()
        );

        // Build a minimal OSPF Hello with a fake router-id (99.99.99.99)
        // and a fake source (172.30.0.99) so it doesn't collide with
        // anything real. It targets 224.0.0.5 (AllSPFRouters).
        // Open a TX socket (new unnamed unix-dgram), sendto the server path.
        let tx = UnixDatagram::unbound()?;
        let vpp_server_path = reply.pathname.trim_end_matches('\0').to_string();

        // ---- Test 1: MULTICAST injection via PUNT_L2 ----
        // Multicast destinations (224.0.0.5 for AllSPFRouters) cannot
        // use PUNT_IP4_ROUTED because that enqueues at ip4-lookup
        // (the UNICAST FIB node), which has no 224.0.0.5/32 entry and
        // returns the drop adjacency. PUNT_L2 goes directly to
        // <iface>-output and requires a full L2 frame.
        //
        // Multicast MAC: 01:00:5e:<low-23-bits-of-group>
        //   224.0.0.5 -> 01:00:5e:00:00:05
        {
            let ip_pkt = build_test_ospf_hello(
                [172, 30, 0, 99],
                [224, 0, 0, 5],
                [99, 99, 99, 99],
            );
            let src_mac = wan.l2_address;
            let dst_mac = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x05];
            let mut frame = Vec::with_capacity(14 + ip_pkt.len());
            frame.extend_from_slice(&dst_mac);
            frame.extend_from_slice(&src_mac[..6]);
            frame.extend_from_slice(&0x0800u16.to_be_bytes());
            frame.extend_from_slice(&ip_pkt);

            let mut dgram = Vec::with_capacity(8 + frame.len());
            dgram.extend_from_slice(&wan.sw_if_index.to_le_bytes());
            dgram.extend_from_slice(&PUNT_ACTION_L2.to_le_bytes());
            dgram.extend_from_slice(&frame);
            println!(
                "[TX-mcast] {} byte dgram, PUNT_L2 172.30.0.99 -> 224.0.0.5",
                dgram.len()
            );
            match tx.send_to(&dgram, &vpp_server_path) {
                Ok(n) => println!("[TX-mcast] sendto ok: {}", n),
                Err(e) => println!("[TX-mcast] sendto error: {}", e),
            }
        }

        // ---- Test 2: UNICAST injection via PUNT_IP4_ROUTED ----
        // Unicast destinations CAN use PUNT_IP4_ROUTED because ip4-lookup
        // walks the unicast FIB and finds a real adjacency for any
        // address on a directly-connected subnet. The packet enters at
        // ip4-lookup, gets rewritten with the right L2 header by
        // ip4-rewrite (using VPP's ARP/ND tables), and egresses via
        // interface-output. Simpler than PUNT_L2 because we don't need
        // to construct the L2 header ourselves.
        //
        // Target: 172.30.0.1 (frr-outer) — a real neighbor on the
        // test-VM topology. It'll receive a spurious OSPF Hello from
        // router-id 99.99.99.99 and log it; no state impact since
        // router_id 99.99.99.99 never responds to subsequent traffic.
        {
            let ip_pkt = build_test_ospf_hello(
                [172, 30, 0, 99],
                [172, 30, 0, 1],
                [99, 99, 99, 99],
            );
            let mut dgram = Vec::with_capacity(8 + ip_pkt.len());
            dgram.extend_from_slice(&wan.sw_if_index.to_le_bytes());
            dgram.extend_from_slice(&PUNT_ACTION_IP4_ROUTED.to_le_bytes());
            dgram.extend_from_slice(&ip_pkt);
            println!(
                "[TX-ucast] {} byte dgram, PUNT_IP4_ROUTED 172.30.0.99 -> 172.30.0.1",
                dgram.len()
            );
            match tx.send_to(&dgram, &vpp_server_path) {
                Ok(n) => println!("[TX-ucast] sendto ok: {}", n),
                Err(e) => println!("[TX-ucast] sendto error: {}", e),
            }
        }

        println!("[+] TX done, now listening to see the echo (and any real traffic)...\n");
    }

    // Step 3: read datagrams with a 60-second overall timeout.
    // We use non-blocking reads with a tokio timer so Ctrl-C works cleanly.
    rx.set_nonblocking(true)?;
    let rx = tokio::net::UnixDatagram::from_std(rx)?;

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut packet_count = 0;
    let mut buf = vec![0u8; 65536];
    println!("[+] listening for OSPF packets (60s)...\n");

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

        // Decode punt_packetdesc_t (8 bytes, little-endian on x86):
        //   u32 sw_if_index
        //   u32 action    (enum punt_action_e)
        let sw_if_index = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let action = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let payload = &buf[8..n];

        println!(
            "[#{}] {} bytes  sw_if_index={} action={}  payload={} bytes",
            packet_count, n, sw_if_index, action, payload.len()
        );

        // Try to decode as ethernet + ipv4.
        if payload.len() >= 14 {
            let ethertype = u16::from_be_bytes([payload[12], payload[13]]);
            let dst_mac = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                payload[0], payload[1], payload[2], payload[3], payload[4], payload[5]
            );
            let src_mac = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                payload[6], payload[7], payload[8], payload[9], payload[10], payload[11]
            );
            println!(
                "    L2: dst={} src={} ethertype=0x{:04x}",
                dst_mac, src_mac, ethertype
            );
            if ethertype == 0x0800 && payload.len() >= 34 {
                let ip = &payload[14..];
                let version_ihl = ip[0];
                let ttl = ip[8];
                let proto = ip[9];
                let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
                let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
                println!(
                    "    L3: ver=0x{:x} ttl={} proto={} {} -> {}",
                    version_ihl, ttl, proto, src, dst
                );
                if proto == 89 && payload.len() >= 14 + 24 {
                    // OSPF header: version, type, length, router_id
                    let off = 14 + ((ip[0] & 0x0f) as usize) * 4;
                    if payload.len() >= off + 24 {
                        let ospf = &payload[off..];
                        let ver = ospf[0];
                        let typ = ospf[1];
                        let len = u16::from_be_bytes([ospf[2], ospf[3]]);
                        let rid = format!(
                            "{}.{}.{}.{}",
                            ospf[4], ospf[5], ospf[6], ospf[7]
                        );
                        let type_name = match typ {
                            1 => "Hello",
                            2 => "DB-Desc",
                            3 => "LS-Req",
                            4 => "LS-Update",
                            5 => "LS-Ack",
                            _ => "?",
                        };
                        println!(
                            "    OSPF: v{} {} len={} router_id={}",
                            ver, type_name, len, rid
                        );
                    }
                }
            }
        }
        println!();
    }

    println!("[+] deregistering...");
    let dreply: PuntSocketDeregisterReply = client
        .request::<PuntSocketDeregister, PuntSocketDeregisterReply>(PuntSocketDeregister {
            punt_type: PuntType::IpProto,
            af: AF_IPV4,
            protocol: IP_PROTO_OSPF,
            port: 0,
        })
        .await?;
    println!("[+] deregister retval={}", dreply.retval);

    // Best-effort cleanup
    let _ = std::fs::remove_file(CLIENT_SOCKET);

    println!("\n[+] done. captured {} packets.", packet_count);
    Ok(())
}
