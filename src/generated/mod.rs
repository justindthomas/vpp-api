//! Auto-generated VPP API message types.
//!
//! These modules are generated from VPP's `.api.json` files by the
//! codegen tool in `vpp-api/codegen/`. They define Rust structs for
//! each VPP API message with encode/decode methods for the binary
//! wire protocol.
//!
//! To regenerate after a VPP version change:
//!   1. Copy updated .api.json files from /usr/share/vpp/api/ into api-json/
//!   2. Run: cargo run --bin vpp-api-codegen
//!   3. Commit the regenerated files

pub mod vpe;
pub mod interface;
pub mod ip;
pub mod ip_neighbor;
pub mod punt;
pub mod dhcp;
pub mod lcp;
