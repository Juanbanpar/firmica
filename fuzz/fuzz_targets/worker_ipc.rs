#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    firmica_fuzz::worker_ipc(input);
});
