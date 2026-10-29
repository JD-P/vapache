#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    vapached::cgi::fuzz_parse_cgi_response(data);
});
