#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    vapached::fastcgi::fuzz_parse_fastcgi_records(data);
});
