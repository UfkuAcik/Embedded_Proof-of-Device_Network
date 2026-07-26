use std::borrow::Cow;

pub fn corpus_bytes(input: &[u8]) -> Cow<'_, [u8]> {
    let Some(hex) = input.strip_prefix(b"hex:") else {
        return Cow::Borrowed(input);
    };
    let digits = hex
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if digits.len() % 2 != 0 {
        return Cow::Borrowed(input);
    }
    let mut decoded = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        let Some(high) = nibble(pair[0]) else {
            return Cow::Borrowed(input);
        };
        let Some(low) = nibble(pair[1]) else {
            return Cow::Borrowed(input);
        };
        decoded.push((high << 4) | low);
    }
    Cow::Owned(decoded)
}

fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
