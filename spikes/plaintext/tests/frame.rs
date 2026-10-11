//! Go's frame: parsed in place, accepted and rejected as today's transport
//! decoder does (with the differences physical plus logical makes), and
//! written back byte for byte.

mod common;

use common::{decode, malformed, representable, valid, UNREPRESENTABLE};
use vitaminc_aead_value::transport::{decode_value, Reader};
use vitaminc_aead_value::Value;
use vitaminc_plaintext_spike::scalar::LOGICAL;
use vitaminc_plaintext_spike::{to_frame, Frame};
use vitaminc_protected::Controlled;

#[test]
fn frames_round_trip_through_the_frame_writer() {
    for v in representable() {
        let frame = Frame::parse(&v.bytes).expect(&v.name);
        assert_eq!(to_frame(frame).unwrap().risky_ref(), &v.bytes[..], "{}", v.name);
        // And today's decoder agrees it's a value.
        decode(&v.bytes);
    }
}

#[test]
fn values_with_no_physical_plus_logical_form_are_refused() {
    for v in valid().into_iter().filter(|v| UNREPRESENTABLE.contains(&v.name.as_str())) {
        decode(&v.bytes);
        assert!(Frame::parse(&v.bytes).is_err(), "{}", v.name);
    }
}

#[test]
fn frame_parse_rejects_the_malformed_corpus() {
    for v in malformed() {
        assert!(decode_value(&mut Reader::new(&v.bytes)).is_err(), "decoder: {}", v.name);
        assert!(Frame::parse(&v.bytes).is_err(), "frame: {}", v.name);
    }
}

/// Today's decoder accepts these and the spike refuses them.
fn unrepresentable(value: &Value) -> bool {
    match value {
        Value::Timestamp(ts) => ts.timestamp_subsec_nanos() >= 1_000_000_000,
        Value::Decimal(d) => d.is_zero() && d.is_sign_negative(),
        Value::Array(items) => items.iter().any(unrepresentable),
        Value::Object(entries) => entries.iter().any(|(_, v)| unrepresentable(v)),
        Value::Passthrough(v) => unrepresentable(v),
        _ => false,
    }
}

/// Agreement with today's decoder, except where the spike differs on
/// purpose: the logical envelope (new) and the two unrepresentable values.
#[test]
fn frame_parse_agrees_with_the_decoder_on_mutated_input() {
    // xorshift, fixed seed: deterministic.
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut seeds: Vec<Vec<u8>> = valid().into_iter().map(|v| v.bytes).collect();
    // Envelope seeds, so mutations reach the new tag too.
    seeds.push(vec![0xF3, 3, 1, 0x05, 0x7B, 0, 0, 0, 0, 0, 0, 0]);
    seeds.push(vec![0xF3, 0x7F, 9, 0x0A, 2, 0, 0, 0, b'h', b'i']);
    let (mut new, mut refused) = (0, 0);
    for _ in 0..20_000 {
        let mut bytes = seeds[next() as usize % seeds.len()].clone();
        match next() % 4 {
            0 if !bytes.is_empty() => {
                let i = next() as usize % bytes.len();
                bytes[i] = next() as u8;
            }
            1 if !bytes.is_empty() => bytes.truncate(next() as usize % bytes.len()),
            2 => bytes.push(next() as u8),
            _ if !bytes.is_empty() => {
                let i = next() as usize % bytes.len();
                bytes[i] ^= 1 << (next() % 8);
            }
            _ => {}
        }
        let decoder = decode_value(&mut Reader::new(&bytes));
        match (Frame::parse(&bytes).is_ok(), decoder) {
            (true, Ok(_)) | (false, Err(_)) => {}
            (true, Err(_)) => {
                assert!(bytes.contains(&LOGICAL), "{bytes:02x?}");
                new += 1;
            }
            (false, Ok(value)) => {
                assert!(unrepresentable(&value), "{bytes:02x?}");
                refused += 1;
            }
        }
    }
    println!("{new} accepted only by the spike, {refused} refused only by the spike");
}
