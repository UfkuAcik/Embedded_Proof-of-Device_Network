#![no_main]

mod common;

use epdn_protocol::EpochChallenge;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let input = common::corpus_bytes(input);
    if let Ok(challenge) = EpochChallenge::decode(&input) {
        let canonical = challenge
            .canonical_bytes()
            .expect("decoded challenge must remain encodable");
        assert_eq!(canonical, input.as_ref());
    }
});
