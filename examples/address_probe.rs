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

use vpp_api::generated::dhcp::*;
use vpp_api::generated::interface::*;
use vpp_api::generated::ip::*;
use vpp_api::generated::l2::*;
use vpp_api::generated::lcp::*;
use vpp_api::generated::sfw::*;
use vpp_api::generated::vpe::*;
use vpp_api::VppClient;

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
        "create_loopback_instance_d36a3ee2",
        "delete_loopback_f9e6675e",
        "create_vlan_subif_af34ac8b",
        "delete_subif_f9e6675e",
        "dhcp_client_config_1af013ea",
        "dhcp6_client_enable_disable_ae6cfcfb",
        "lcp_itf_pair_add_del_40482b80",
        "bridge_domain_add_del_v2_600b7170",
        "sw_interface_set_l2_bridge_d0678b13",
        "sfw_enable_disable_3865946c",
        "sfw_zone_interface_add_del_66c8cf1c",
        "sfw_policy_add_del_bb931f93",
        "sfw_policy_rule_add_del_2fa9c963",
        "sfw_nat_pool_add_del_104621ad",
        "sfw_nat_static_add_del_1ea19567",
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
    // avoid colliding with real config. Now via binary API instead
    // of vppctl.
    println!("\nCreating loopback instance 99 via create_loopback_instance...");
    let reply: CreateLoopbackInstanceReply = client
        .request(CreateLoopbackInstance::instance(99))
        .await?;
    assert_eq!(reply.retval, 0, "create_loopback_instance failed");
    let sw_if_index = reply.sw_if_index;
    println!("  sw_if_index = {}", sw_if_index);

    // Bring it admin-up so addresses stick.
    let up: SwInterfaceSetFlagsReply = client
        .request(SwInterfaceSetFlags {
            sw_if_index,
            flags: IfStatusFlags(IfStatusFlags::ADMIN_UP),
        })
        .await?;
    assert_eq!(up.retval, 0);

    // Find its name for pretty-printing.
    let interfaces = client
        .dump::<SwInterfaceDump, SwInterfaceDetails>(SwInterfaceDump::default())
        .await?;
    let name = interfaces
        .iter()
        .find(|i| i.sw_if_index == sw_if_index)
        .map(|i| i.interface_name.clone())
        .unwrap_or_else(|| format!("sw_if_index:{}", sw_if_index));
    println!("  name = {}", name);

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
    // LCP pair round-trip — creates a Linux TAP mirroring the
    // loopback. Skip if the linux_cp plugin isn't loaded (VPP will
    // return a negative retval like -7).
    println!("\nRound-tripping lcp_itf_pair_add_del...");
    let lr: LcpItfPairAddDelReply = client
        .request(LcpItfPairAddDel::add_tap(sw_if_index, "probe-lo99"))
        .await?;
    println!("  add retval = {}", lr.retval);
    if lr.retval == 0 {
        let lr: LcpItfPairAddDelReply = client
            .request(LcpItfPairAddDel::del(sw_if_index))
            .await?;
        println!("  del retval = {}", lr.retval);
    } else {
        println!("  (linux_cp plugin may not be loaded; skipping del)");
    }

    // DHCPv6 enable/disable round-trip — safe on a loopback; VPP
    // just configures the state without emitting wire traffic.
    println!("\nRound-tripping dhcp6_client_enable_disable...");
    let re: Dhcp6ClientEnableDisableReply = client
        .request(Dhcp6ClientEnableDisable {
            sw_if_index,
            enable: true,
        })
        .await?;
    println!("  enable retval = {}", re.retval);
    let re: Dhcp6ClientEnableDisableReply = client
        .request(Dhcp6ClientEnableDisable {
            sw_if_index,
            enable: false,
        })
        .await?;
    println!("  disable retval = {}", re.retval);

    println!("\nDeleting loopback via delete_loopback...");
    let del: DeleteLoopbackReply = client.request(DeleteLoopback { sw_if_index }).await?;
    assert_eq!(del.retval, 0, "delete_loopback failed");

    // Bridge domain + BVI round-trip — create BD, attach a fresh
    // loopback as the BVI, detach, destroy.
    println!("\nRound-tripping bridge_domain_add_del_v2 + sw_interface_set_l2_bridge...");
    let bvi: CreateLoopbackReply = client
        .request(CreateLoopback {
            mac_address: [0; 6],
        })
        .await?;
    assert_eq!(bvi.retval, 0);
    let bd: BridgeDomainAddDelV2Reply = client
        .request(BridgeDomainAddDelV2::add(999))
        .await?;
    println!(
        "  bridge_domain_add_del_v2 retval={} bd_id={}",
        bd.retval, bd.bd_id
    );
    assert_eq!(bd.retval, 0);
    let attach: SwInterfaceSetL2BridgeReply = client
        .request(SwInterfaceSetL2Bridge::attach_bvi(bvi.sw_if_index, bd.bd_id))
        .await?;
    println!("  attach BVI retval={}", attach.retval);
    assert_eq!(attach.retval, 0);
    let detach: SwInterfaceSetL2BridgeReply = client
        .request(SwInterfaceSetL2Bridge::detach(bvi.sw_if_index))
        .await?;
    println!("  detach retval={}", detach.retval);
    let del_bd: BridgeDomainAddDelV2Reply = client
        .request(BridgeDomainAddDelV2::del(bd.bd_id))
        .await?;
    println!("  bridge_domain del retval={}", del_bd.retval);
    let _: DeleteLoopbackReply = client
        .request(DeleteLoopback {
            sw_if_index: bvi.sw_if_index,
        })
        .await?;

    // Quick round-trip on create_vlan_subif / delete_subif using a
    // fresh parent loopback (VLAN sub-interfaces are valid on
    // loopbacks).
    println!("\nRound-tripping create_vlan_subif / delete_subif on a scratch loopback...");
    let parent: CreateLoopbackReply = client
        .request(CreateLoopback {
            mac_address: [0; 6],
        })
        .await?;
    assert_eq!(parent.retval, 0);
    let sub: CreateVlanSubifReply = client
        .request(CreateVlanSubif {
            sw_if_index: parent.sw_if_index,
            vlan_id: 777,
        })
        .await?;
    assert_eq!(sub.retval, 0, "create_vlan_subif failed");
    println!("  parent sw_if_index={}  subif sw_if_index={}", parent.sw_if_index, sub.sw_if_index);
    let ds: DeleteSubifReply = client
        .request(DeleteSubif {
            sw_if_index: sub.sw_if_index,
        })
        .await?;
    assert_eq!(ds.retval, 0, "delete_subif failed");
    let dp: DeleteLoopbackReply = client
        .request(DeleteLoopback {
            sw_if_index: parent.sw_if_index,
        })
        .await?;
    assert_eq!(dp.retval, 0);

    // SFW plugin: round-trip the full mutation API — zone attach,
    // policy create, rule add+del, policy delete, NAT pool, NAT
    // static. Requires the sfw plugin to be loaded.
    println!("\nRound-tripping sfw_zone_interface_add_del...");
    let lb: CreateLoopbackReply = client
        .request(CreateLoopback { mac_address: [0; 6] })
        .await?;
    assert_eq!(lb.retval, 0);
    let add: SfwZoneInterfaceAddDelReply = client
        .request(SfwZoneInterfaceAddDel {
            is_add: true,
            sw_if_index: lb.sw_if_index,
            zone_name: "probe-zone".to_string(),
        })
        .await?;
    println!("  zone add retval = {}", add.retval);
    // Add a second zone so we have a zone-pair to hang a policy on.
    let _: SfwZoneInterfaceAddDelReply = client
        .request(SfwZoneInterfaceAddDel {
            is_add: true,
            sw_if_index: lb.sw_if_index,
            zone_name: "probe-peer".to_string(),
        })
        .await?;

    println!("\nRound-tripping sfw_policy_add_del...");
    let pol: SfwPolicyAddDelReply = client
        .request(SfwPolicyAddDel {
            is_add: true,
            policy_name: "probe-pol".to_string(),
            from_zone: "probe-zone".to_string(),
            to_zone: "probe-peer".to_string(),
            default_action: SfwAction::Deny,
            implicit_icmpv6: true,
        })
        .await?;
    println!("  create retval = {}", pol.retval);
    assert_eq!(pol.retval, 0, "policy create");

    println!("\nRound-tripping sfw_policy_rule_add_del...");
    let rule_add: SfwPolicyRuleAddDelReply = client
        .request(SfwPolicyRuleAddDel::any(
            "probe-pol",
            0,
            SfwAction::Permit,
        ))
        .await?;
    println!("  rule add retval = {}", rule_add.retval);
    let rule_del: SfwPolicyRuleAddDelReply = client
        .request(SfwPolicyRuleAddDel::del("probe-pol", 0))
        .await?;
    println!("  rule del retval = {}", rule_del.retval);

    let pol_del: SfwPolicyAddDelReply = client
        .request(SfwPolicyAddDel {
            is_add: false,
            policy_name: "probe-pol".to_string(),
            from_zone: String::new(),
            to_zone: String::new(),
            default_action: SfwAction::Deny,
            implicit_icmpv6: false,
        })
        .await?;
    println!("  policy del retval = {}", pol_del.retval);

    println!("\nRound-tripping sfw_nat_pool_add_del...");
    let pool_add: SfwNatPoolAddDelReply = client
        .request(SfwNatPoolAddDel {
            is_add: true,
            external_prefix: Prefix::ipv4([203, 0, 113, 0], 28),
            internal_prefix: Prefix::ipv4([10, 77, 0, 0], 24),
            mode: SfwNatMode::Dynamic,
        })
        .await?;
    println!("  pool add retval = {}", pool_add.retval);
    assert_eq!(pool_add.retval, 0, "pool add");
    let pool_del: SfwNatPoolAddDelReply = client
        .request(SfwNatPoolAddDel {
            is_add: false,
            external_prefix: Prefix::ipv4([203, 0, 113, 0], 28),
            internal_prefix: Prefix::ipv4([10, 77, 0, 0], 24),
            mode: SfwNatMode::Dynamic,
        })
        .await?;
    println!("  pool del retval = {}", pool_del.retval);

    println!("\nRound-tripping sfw_nat_static_add_del...");
    let st_add: SfwNatStaticAddDelReply = client
        .request(SfwNatStaticAddDel::one_to_one_ipv4(
            [198, 51, 100, 1],
            [192, 168, 100, 1],
            true,
        ))
        .await?;
    println!("  static add retval = {}", st_add.retval);
    let st_del: SfwNatStaticAddDelReply = client
        .request(SfwNatStaticAddDel::one_to_one_ipv4(
            [198, 51, 100, 1],
            [192, 168, 100, 1],
            false,
        ))
        .await?;
    println!("  static del retval = {}", st_del.retval);

    // Clean up the zone attachments + scratch loopback.
    let _: SfwZoneInterfaceAddDelReply = client
        .request(SfwZoneInterfaceAddDel {
            is_add: false,
            sw_if_index: lb.sw_if_index,
            zone_name: "probe-zone".to_string(),
        })
        .await?;
    let _: SfwZoneInterfaceAddDelReply = client
        .request(SfwZoneInterfaceAddDel {
            is_add: false,
            sw_if_index: lb.sw_if_index,
            zone_name: "probe-peer".to_string(),
        })
        .await?;
    let _: DeleteLoopbackReply = client
        .request(DeleteLoopback {
            sw_if_index: lb.sw_if_index,
        })
        .await?;

    // Final control_ping to ensure connection is still healthy.
    let ping: ControlPingReply = client.request(ControlPing).await?;
    assert_eq!(ping.retval, 0);
    println!("\nAll checks passed.");
    Ok(())
}
