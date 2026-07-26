#![no_main]

mod common;

use epdn_protocol::TicketSubmission;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let input = common::corpus_bytes(input);
    if let Ok(submission) = TicketSubmission::decode(&input) {
        let canonical = submission
            .canonical_bytes()
            .expect("decoded submission must remain encodable");
        assert_eq!(canonical, input.as_ref());
    }
});
