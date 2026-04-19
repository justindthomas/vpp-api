//! Live validation for the Phase 2a interface bindings.
//!
//! Creates a loopback, adds an IPv4 + an IPv6 address via
//! `sw_interface_add_del_address`, reads them back via
//! `ip_address_dump`, bumps MTU via `sw_interface_set_mtu`, toggles
//! IPv6 via `sw_interface_ip6_enable_disable`, then cleans up.
//!
//! Run against a live VPP:
//!   cargo run --example address_probe
//! (defaults to /run/vpp/core-api.sock)

use vpp_api::generated::interface::*;
use vpp_api::generated::ip::*;
use vpp_api::generated::vpe::*;
use vpp_api::VppClient;

async fn cli(client: &VppClient, cmd: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Use vppctl socket via CliInband — but we don't have that message
    // yet, so we'll use a side-channel: tokio's Command to invoke
    // vppctl. Just for setup/cleanup of the scratch loopback.
    let out = tokio::process::Command::new("vppctl")
        .arg("-s")
        .arg("/run/vpp/core-cli.sock")
        .arg(cmd)
        .output()
        .await?;
    let _ = client; // keep signature symmetric
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let socket_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/run/vpp/core-api.sock".to_string());
    println!("Connecting to VPP at {}...", socket_path);
    let client = VppClient::connect(&socket_path).await?;
    println!(
        "Connected. client_index={}, {} messages in table",
        client.client_index(),
        client.message_table().len()
    );

    // Confirm our new message names resolve during handshake.
    for name in &[
        "sw_interface_add_del_address_5463d73b",
        "sw_interface_set_mtu_5cbe85e5",
        "sw_interface_ip6_enable_disable_ae6cfcfb",
    ] {
        match client.message_table().get(*name) {
            Some(id) => println!("  msg_id({}) = {}", name, id),
            None => {
                eprintln!("  MISSING: {} — wire format mismatch with VPP", name);
                std::process::exit(2);
            }
        }
    }

    // Set up a scratch loopback for the test. Use instance 99 to
    // avoid colliding with real config.
    println!("\nCreating loopback instance 99 via vppctl...");
    let out = cli(&client, "create loopback interface instance 99").await?;
    let name = out.trim().to_string();
    if name.is_empty() {
        eprintln!("failed to create loopback (vppctl returned nothing)");
        std::process::exit(3);
    }
    println!("  Created {}", name);

    let _ = cli(&client, &format!("set interface state {} up", name)).await?;

    // Find its sw_if_index via a fresh dump.
    let interfaces = client
        .dump::<SwInterfaceDump, SwInterfaceDetails>(SwInterfaceDump::default())
        .await?;
    let sw_if_index = interfaces
        .iter()
        .find(|i| i.interface_name == name)
        .map(|i| i.sw_if_index)
        .ok_or("loopback not found in dump")?;
    println!("  sw_if_index = {}", sw_if_index);

    // --- sw_interface_add_del_address IPv4 ---
    println!("\nAdding 203.0.113.9/32...");
    let prefix_v4 = Prefix::ipv4([203, 0, 113, 9], 32);
    let reply: SwInterfaceAddDelAddressReply = client
        .request(SwInterfaceAddDelAddress {
            sw_if_index,
            is_add: true,
            del_all: false,
            prefix: prefix_v4.clone(),
        })
        .await?;
    println!("  retval = {}", reply.retval);
    assert_eq!(reply.retval, 0, "add v4 failed");

    // --- sw_interface_add_del_address IPv6 ---
    println!("Adding 2001:db8:dead::beef/128...");
    let prefix_v6 = Prefix::ipv6(
        [
            0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0xbe, 0xef,
        ],
        128,
    );
    let reply: SwInterfaceAddDelAddressReply = client
        .request(SwInterfaceAddDelAddress {
            sw_if_index,
            is_add: true,
            del_all: false,
            prefix: prefix_v6.clone(),
        })
        .await?;
    println!("  retval = {}", reply.retval);
    assert_eq!(reply.retval, 0, "add v6 failed");

    // --- ip_address_dump read-back ---
    println!("\nReading back addresses via ip_address_dump...");
    for is_v6 in [false, true] {
        let addrs = client
            .dump::<IpAddressDump, IpAddressDetails>(IpAddressDump {
                sw_if_index,
                is_ipv6: is_v6,
            })
            .await?;
        println!("  is_ipv6={}: {} entries", is_v6, addrs.len());
        for a in &addrs {
            let prefix = &a.prefix;
            let addr = match prefix.af {
                AddressFamily::Ipv4 => format!(
                    "{}.{}.{}.{}",
                    prefix.address[0], prefix.address[1], prefix.address[2], prefix.address[3]
                ),
                AddressFamily::Ipv6 => std::net::Ipv6Addr::from(prefix.address).to_string(),
            };
            println!("    {}/{}", addr, prefix.len);
        }
    }

    // --- sw_interface_set_mtu ---
    println!("\nSetting MTU to 9000...");
    let reply: SwInterfaceSetMtuReply = client
        .request(SwInterfaceSetMtu::packet(sw_if_index, 9000))
        .await?;
    println!("  retval = {}", reply.retval);
    assert_eq!(reply.retval, 0, "set_mtu failed");

    // --- sw_interface_ip6_enable_disable ---
    println!("Toggling IPv6 off then on...");
    let reply: SwInterfaceIp6EnableDisableReply = client
        .request(SwInterfaceIp6EnableDisable {
            sw_if_index,
            enable: false,
        })
        .await?;
    println!("  disable retval = {}", reply.retval);
    let reply: SwInterfaceIp6EnableDisableReply = client
        .request(SwInterfaceIp6EnableDisable {
            sw_if_index,
            enable: true,
        })
        .await?;
    println!("  enable  retval = {}", reply.retval);

    // --- Cleanup ---
    println!("\nRemoving addresses...");
    let _: SwInterfaceAddDelAddressReply = client
        .request(SwInterfaceAddDelAddress {
            sw_if_index,
            is_add: false,
            del_all: false,
            prefix: prefix_v4,
        })
        .await?;
    let _: SwInterfaceAddDelAddressReply = client
        .request(SwInterfaceAddDelAddress {
            sw_if_index,
            is_add: false,
            del_all: false,
            prefix: prefix_v6,
        })
        .await?;
    println!("Deleting loopback...");
    let _ = cli(&client, &format!("delete loopback interface intfc {}", name)).await?;

    // Final control_ping to ensure connection is still healthy.
    let ping: ControlPingReply = client.request(ControlPing).await?;
    assert_eq!(ping.retval, 0);
    println!("\nAll checks passed.");
    Ok(())
}
