// What a scheme derives for a space is as secret as its key, so a space
// must wipe itself on drop: a bare `Vec<u8>` of derived bytes does not
// compile. `Protected`, a cipher that wipes on drop, or `()` does.

use core::convert::Infallible;
use vitaminc_ore::{Context, OrderPlaintext, OrderScheme};

struct Leaky;

impl OrderScheme for Leaky {
    const NAME: &'static str = "leaky";
    type Term = Vec<u8>;
    type Error = Infallible;
    type Space = Vec<u8>;

    fn open(&self, _: vitaminc_ore::OrderTarget, salt: &Context<'_>) -> Result<Vec<u8>, Infallible> {
        Ok(salt.as_bytes().to_vec())
    }

    fn encrypt_plaintext(&self, _: &Vec<u8>, _: &OrderPlaintext) -> Result<Vec<u8>, Infallible> {
        Ok(Vec::new())
    }

    fn compare(a: &Vec<u8>, b: &Vec<u8>) -> Option<core::cmp::Ordering> {
        Some(a.cmp(b))
    }
}

fn main() {}
