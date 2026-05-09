#![no_main]

use libfuzzer_sys::fuzz_target;
use vpp_api::VppMessage;
use vpp_api::generated::ip::IpRouteDetails;

fuzz_target!(|data: &[u8]| {
    let _ = IpRouteDetails::decode_fields(data);
});
