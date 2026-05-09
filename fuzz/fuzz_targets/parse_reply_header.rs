#![no_main]

use libfuzzer_sys::fuzz_target;
use vpp_api::codec::parse_reply_header;

fuzz_target!(|data: &[u8]| {
    let _ = parse_reply_header(data);
});
