//! Tests for `SchemeVisitor`. The scheme it returns is the scheme keyed
//! with the block the PRF derives. That scheme encrypts a borrowed
//! plaintext after the key arrives, so the plaintext is never passed to
//! the PRF call.

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

/// Keys a scheme with `SchemeVisitor`, under the given context.
fn keyed(context: &[u8]) -> Mock {
    context
        .prf_visit_with_context(&prf(), "order", SchemeVisitor::<Mock>::new())
        .into_result()
        .expect("keys")
}

/// Keys the same scheme by hand, with the block that `BlockVisitor`
/// derives under the given context.
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

/// A caller needs only the keyed scheme to encrypt. A borrowed plaintext,
/// under a target chosen at runtime, gives the same term as the owned
/// value. The visitor itself never takes a plaintext.
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
        .encrypt_checked(surname)
        .expect("encrypts");
    assert_eq!(borrowed.as_ref(), owned.as_ref());
}

/// A block of any length keys a scheme whose key is an array of that
/// length. The length is not limited to 32 bytes.
#[test]
fn a_block_of_any_length_keys_a_scheme_of_that_length() {
    use vitaminc_ore::OrderScheme;
    use vitaminc_prf::ResolvedPrf;

    struct Wide(Protected<[u8; 64]>);
    impl OrderScheme for Wide {
        const NAME: &'static str = "wide";
        type Term = Vec<u8>;
        type Error = core::convert::Infallible;
        type Space = ();
        fn open(&self, _: OrderTarget, _: &vitaminc_ore::Context<'_>) -> Result<(), Self::Error> {
            Ok(())
        }
        fn encrypt_plaintext(
            &self,
            _: &(),
            _: &vitaminc_ore::OrderPlaintext,
        ) -> Result<Vec<u8>, Self::Error> {
            use vitaminc_protected::Controlled;
            Ok(self.0.risky_ref().to_vec())
        }
        fn compare(a: &Vec<u8>, b: &Vec<u8>) -> Option<core::cmp::Ordering> {
            Some(a.cmp(b))
        }
    }
    impl OrderKeyInit for Wide {
        type Key = Protected<[u8; 64]>;
        type KeyError = core::convert::Infallible;
        fn new(key: Self::Key) -> Self {
            Self(key)
        }
        fn try_from_bytes(_: Protected<Vec<u8>>) -> Result<Self, Self::KeyError> {
            Ok(Self(Protected::new([0; 64])))
        }
    }

    let wide = ResolvedPrf::<[u8; 64], ()>::Block([9; 64])
        .visit(SchemeVisitor::<Wide>::new())
        .expect("keys");
    use vitaminc_protected::Controlled;
    assert_eq!(wide.0.risky_ref(), &[9; 64]);
}

/// The visitor's `Debug` output is only its name, because the visitor
/// contains no data.
#[test]
fn a_visitor_debugs_as_its_name() {
    assert_eq!(
        format!("{:?}", SchemeVisitor::<Mock>::default()),
        "SchemeVisitor"
    );
}

/// Only a single block keys a scheme. The visitor refuses every other
/// shape, including a sequence or map with blocks in it at any depth.
#[test]
fn every_shape_but_a_block_is_refused() {
    use vitaminc_prf::{PrfVisitorError, ResolvedPrf};

    type Node = ResolvedPrf<[u8; 32], ()>;
    let shapes: [(&str, Node); 4] = [
        ("absent", ResolvedPrf::Absent),
        ("passthrough", ResolvedPrf::Passthrough(())),
        (
            "sequence",
            ResolvedPrf::Sequence(vec![
                ResolvedPrf::Block([1; 32]),
                ResolvedPrf::Sequence(vec![ResolvedPrf::Block([2; 32])]),
                ResolvedPrf::Absent,
            ]),
        ),
        (
            "map",
            ResolvedPrf::Map(vec![
                (String::from("a"), ResolvedPrf::Block([3; 32])),
                (
                    String::from("b"),
                    ResolvedPrf::Map(vec![(String::from("c"), ResolvedPrf::Block([4; 32]))]),
                ),
                (String::from("d"), ResolvedPrf::Passthrough(())),
            ]),
        ),
    ];
    for (name, node) in shapes {
        assert!(
            matches!(
                node.visit(SchemeVisitor::<Mock>::new()),
                Err(PrfVisitorError::UnexpectedShape)
            ),
            "{name} keyed a scheme"
        );
    }
}
