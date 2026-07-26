#![no_main]

mod common;

use epdn_protocol::SignedTransfer;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let input = common::corpus_bytes(input);
    if let Ok(transfer) = SignedTransfer::decode(&input) {
        let canonical = transfer
            .canonical_bytes()
            .expect("decoded transfer must remain encodable");
        assert_eq!(canonical, input.as_ref());
    }
});
