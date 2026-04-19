//! Integration test: connect to a running VPP instance and dump interfaces.
//!
//! Run from within the dataplane namespace on a system with VPP running:
//!   cargo run --example connect_test

use vpp_api::generated::interface::SwInterfaceDump;
use vpp_api::generated::vpe::ControlPingReply;
use vpp_api::VppClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let level = if std::env::var("RUST_LOG").is_ok() {
        tracing::Level::TRACE
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(level).init();

    let socket_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/run/vpp/core-api.sock".to_string());

    println!("Connecting to VPP at {}...", socket_path);
    let client = VppClient::connect(&socket_path).await?;
    println!(
        "Connected! client_index={}, {} messages in table",
        client.client_index(),
        client.message_table().len()
    );

    // Print a few known message IDs to verify table lookup works
    for name in &[
        "control_ping_51077d14",
        "control_ping_reply_f6b0b8ca",
        "sw_interface_dump_aa610c27",
        "sw_interface_details_6c221fc7",
        "ip_route_add_del_b8ecfe0d",
    ] {
        match client.message_table().get(*name) {
            Some(id) => println!("  {} -> msg_id={}", name, id),
            None => println!("  {} -> NOT FOUND", name),
        }
    }

    // Send a control_ping to verify request/reply works
    println!("\nSending control_ping...");
    let reply: ControlPingReply = client
        .request::<vpp_api::generated::vpe::ControlPing, ControlPingReply>(
            vpp_api::generated::vpe::ControlPing,
        )
        .await?;
    println!(
        "control_ping_reply: retval={}, vpe_pid={}",
        reply.retval, reply.vpe_pid
    );

    // Dump interfaces
    println!("\nDumping interfaces...");
    let interfaces = client
        .dump::<SwInterfaceDump, vpp_api::generated::interface::SwInterfaceDetails>(
            SwInterfaceDump::default(),
        )
        .await?;

    println!("Got {} interfaces:", interfaces.len());
    for iface in &interfaces {
        let mac = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            iface.l2_address[0],
            iface.l2_address[1],
            iface.l2_address[2],
            iface.l2_address[3],
            iface.l2_address[4],
            iface.l2_address[5]
        );
        println!(
            "  [{}] {} mac={} admin={} link={} mtu={}",
            iface.sw_if_index,
            iface.interface_name,
            mac,
            if iface.flags.is_admin_up() { "up" } else { "down" },
            if iface.flags.is_link_up() { "up" } else { "down" },
            iface.link_mtu,
        );
    }

    // Dump IPv4 routes
    println!("\nDumping IPv4 routes...");
    let routes = client
        .dump::<vpp_api::generated::ip::IpRouteDump, vpp_api::generated::ip::IpRouteDetails>(
            vpp_api::generated::ip::IpRouteDump {
                table: vpp_api::generated::ip::IpTable {
                    table_id: 0,
                    is_ip6: false,
                    name: String::new(),
                },
            },
        )
        .await?;

    println!("Got {} IPv4 routes (showing first 10):", routes.len());
    for route in routes.iter().take(10) {
        let prefix = &route.route.prefix;
        let addr = match prefix.af {
            vpp_api::generated::ip::AddressFamily::Ipv4 => {
                format!("{}.{}.{}.{}", prefix.address[0], prefix.address[1], prefix.address[2], prefix.address[3])
            }
            vpp_api::generated::ip::AddressFamily::Ipv6 => "ipv6".to_string(),
        };
        print!("  {}/{} via", addr, prefix.len);
        for path in &route.route.paths {
            let nh = format!(
                "{}.{}.{}.{}",
                path.nh_addr[0], path.nh_addr[1], path.nh_addr[2], path.nh_addr[3]
            );
            print!(" {} (sw_if_index={}, weight={})", nh, path.sw_if_index, path.weight);
        }
        println!();
    }

    // Test route add/delete
    println!("\nAdding test route 198.51.100.0/24 via 10.0.0.1...");
    use vpp_api::generated::ip::*;
    let add_result: IpRouteAddDelReply = client
        .request::<IpRouteAddDel, IpRouteAddDelReply>(IpRouteAddDel {
            is_add: true,
            is_multipath: false,
            route: IpRoute {
                table_id: 0,
                stats_index: 0,
                prefix: Prefix::ipv4([198, 51, 100, 0], 24),
                n_paths: 1,
                paths: vec![FibPath::via_ipv4([10, 0, 0, 1], u32::MAX)],
            },
        })
        .await?;
    println!("  retval={}, stats_index={}", add_result.retval, add_result.stats_index);

    // Delete the test route
    println!("Deleting test route 198.51.100.0/24...");
    let del_result: IpRouteAddDelReply = client
        .request::<IpRouteAddDel, IpRouteAddDelReply>(IpRouteAddDel {
            is_add: false,
            is_multipath: false,
            route: IpRoute {
                table_id: 0,
                stats_index: 0,
                prefix: Prefix::ipv4([198, 51, 100, 0], 24),
                n_paths: 0,
                paths: vec![],
            },
        })
        .await?;
    println!("  retval={}", del_result.retval);

    println!("\nDone!");
    Ok(())
}
