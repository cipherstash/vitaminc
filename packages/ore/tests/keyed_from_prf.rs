//! A scheme keyed from a PRF with `SchemeVisitor`: it is the scheme keyed
//! with the PRF's block, and it encrypts a borrowed plaintext once the key
//! has arrived, so the plaintext never enters the PRF call.

mod common;

use common::Mock;
use vitaminc_hmac::HmacSha256Prf;
use vitaminc_ore::target::I32;
use vitaminc_ore::{OrderEncrypt, OrderKeyInit, OrderTarget, SchemeVisitor};
use vitaminc_prf::{BlockVisitor, PrfKeyInit, PrfValue};
use vitaminc_protected::Protected;

fn prf() -> HmacSha256Prf {
    HmacSha256Prf::new(Protected::new([7u8; 32]))
}

/// The scheme the visitor returns, under a context.
fn keyed(context: &[u8]) -> Mock {
    context
        .prf_visit_with_context(&prf(), "order", SchemeVisitor::<Mock>::new())
        .into_result()
        .expect("keys")
}

/// The scheme keyed by hand with the same block.
fn by_hand(context: &[u8]) -> Mock {
    let block: [u8; 32] = context
        .prf_visit_with_context(&prf(), "order", BlockVisitor)
        .into_result()
        .expect("derives");
    Mock::new(Protected::new(block))
}

#[test]
fn the_visitor_keys_the_scheme_with_the_prfs_block() {
    let (visited, manual) = (keyed(b"users/age"), by_hand(b"users/age"));
    for value in [-3i32, 0, 42] {
        assert_eq!(
            visited
                .target(I32)
                .encrypt(value)
                .expect("encrypts")
                .as_ref(),
            manual
                .target(I32)
                .encrypt(value)
                .expect("encrypts")
                .as_ref(),
            "{value}"
        );
    }
}

#[test]
fn another_context_keys_another_scheme() {
    let (age, height) = (keyed(b"users/age"), keyed(b"users/height"));
    assert_ne!(
        age.target(I32).encrypt(42i32).expect("encrypts").as_ref(),
        height
            .target(I32)
            .encrypt(42i32)
            .expect("encrypts")
            .as_ref(),
    );
}

/// The plaintext is borrowed, under a target chosen while the program runs,
/// and stays the caller's: nothing was copied into the PRF call.
#[test]
fn a_keyed_scheme_encrypts_a_borrowed_plaintext() {
    let scheme = keyed(b"users/surname");
    let surname = String::from("Lovelace");
    let borrowed = scheme
        .target(OrderTarget::Text)
        .encrypt_checked(&surname)
        .expect("encrypts");
    let owned = scheme
        .target(OrderTarget::Text)
        .encrypt_checked(surname.clone())
        .expect("encrypts");
    assert_eq!(borrowed.as_ref(), owned.as_ref());
    assert_eq!(surname, "Lovelace");
}
