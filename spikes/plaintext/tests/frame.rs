//! Go's frame: parsed in place, accepted and rejected exactly as today's
//! transport decoder does, and written back byte for byte.

mod common;

use common::{decode, malformed, valid};
use vitaminc_aead_value::transport::{decode_value, Reader};
use vitaminc_plaintext_spike::{to_frame, Frame};
use vitaminc_protected::Controlled;

#[test]
fn frames_round_trip_through_the_frame_writer() {
    for v in valid() {
        let frame = Frame::parse(&v.bytes).expect(&v.name);
        assert_eq!(to_frame(frame).unwrap().risky_ref(), &v.bytes[..], "{}", v.name);
        // And today's decoder agrees it's a value.
        decode(&v.bytes);
    }
}

#[test]
fn frame_parse_rejects_the_malformed_corpus() {
    for v in malformed() {
        assert!(decode_value(&mut Reader::new(&v.bytes)).is_err(), "decoder: {}", v.name);
        assert!(Frame::parse(&v.bytes).is_err(), "frame: {}", v.name);
    }
}

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
    let seeds: Vec<Vec<u8>> = valid().into_iter().map(|v| v.bytes).collect();
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
        let decoder = decode_value(&mut Reader::new(&bytes)).is_ok();
        assert_eq!(Frame::parse(&bytes).is_ok(), decoder, "{bytes:02x?}");
    }
}
