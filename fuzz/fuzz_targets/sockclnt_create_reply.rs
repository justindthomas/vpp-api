#![no_main]

use libfuzzer_sys::fuzz_target;
use vpp_api::VppMessage;
use vpp_api::generated::vpe::SockclntCreateReply;

fuzz_target!(|data: &[u8]| {
    let _ = SockclntCreateReply::decode_fields(data);
});
