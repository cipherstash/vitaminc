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

/// The keyed scheme is all a caller needs: a borrowed plaintext, under a
/// target chosen while the program runs, gives the term the owned value
/// does. The visitor itself never takes a plaintext.
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

/// Any key length, not only 32 bytes: a block is keyed into a scheme
/// whose key is an array of the block's length.
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

/// It names itself and nothing else: there is nothing in it to show.
#[test]
fn a_visitor_debugs_as_its_name() {
    assert_eq!(
        format!("{:?}", SchemeVisitor::<Mock>::default()),
        "SchemeVisitor"
    );
}
