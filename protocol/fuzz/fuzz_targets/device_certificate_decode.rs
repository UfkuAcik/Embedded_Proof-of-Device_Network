#![no_main]

mod common;

use epdn_protocol::DeviceCertificate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let input = common::corpus_bytes(input);
    if let Ok(certificate) = DeviceCertificate::decode(&input) {
        let canonical = certificate
            .canonical_bytes()
            .expect("decoded certificate must remain encodable");
        assert_eq!(canonical, input.as_ref());
    }
});
