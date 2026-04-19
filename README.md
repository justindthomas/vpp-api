# vpp-api

Async Rust client for [VPP's](https://fd.io) binary API over Unix sockets.

Handles the 16-byte framing, big-endian serde for message types, and control-ping-based reply streaming. Generated message types for common VPP modules (interface, ip, punt, …) are included under `src/generated/`.

## Build

```sh
cargo build --release
```

## Usage

```rust
use vpp_api::VppClient;

let client = VppClient::connect("/run/vpp/api.sock").await?;
let interfaces = client
    .send_dump(vpp_api::interface::SwInterfaceDump::default())
    .await?;
```

See `examples/` for more complete patterns.

## Codegen

`.api.json` files from a VPP source checkout feed a standalone generator (`codegen/`). Checked-in `api-json/` files come from VPP 25.10 (not yet a submodule of this repo — see TODOs).

## License

MPL-2.0. See [LICENSE](LICENSE).
