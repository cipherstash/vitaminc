//! A scheme for the cases: keeps the bytes as they are.
#![allow(dead_code)]

use core::cmp::Ordering;
use vitaminc_ore::{Context, OrderPlaintext, OrderScheme};
use vitaminc_protected::Controlled;

/// Takes every target.
pub struct Clear;

impl OrderScheme for Clear {
    const NAME: &'static str = "clear";
    type Term = Vec<u8>;
    type Error = core::convert::Infallible;

    fn encrypt_plaintext(
        &self,
        p: &OrderPlaintext,
        _: &Context<'_>,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(p.bytes().risky_ref().clone())
    }

    fn compare(a: &Vec<u8>, b: &Vec<u8>) -> Option<Ordering> {
        Some(a.cmp(b))
    }
}

vitaminc_ore::supports_every_target!(Clear);

/// Takes four-byte targets only, as a block ORE scheme of that width does.
pub struct FourBytes;

impl OrderScheme for FourBytes {
    const NAME: &'static str = "four-bytes";
    type Term = Vec<u8>;
    type Error = core::convert::Infallible;

    fn encrypt_plaintext(
        &self,
        p: &OrderPlaintext,
        _: &Context<'_>,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(p.bytes().risky_ref().clone())
    }

    fn compare(a: &Vec<u8>, b: &Vec<u8>) -> Option<Ordering> {
        Some(a.cmp(b))
    }
}

vitaminc_ore::supports_targets!(FourBytes; I32, Date);

/// Answers for markers only, and forgot the runtime answer.
pub struct Forgetful;

impl OrderScheme for Forgetful {
    const NAME: &'static str = "forgetful";
    type Term = Vec<u8>;
    type Error = core::convert::Infallible;

    fn encrypt_plaintext(
        &self,
        p: &OrderPlaintext,
        _: &Context<'_>,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(p.bytes().risky_ref().clone())
    }

    fn compare(a: &Vec<u8>, b: &Vec<u8>) -> Option<Ordering> {
        Some(a.cmp(b))
    }
}

impl vitaminc_ore::Supports<vitaminc_ore::target::I32> for Forgetful {
    fn supports(_: vitaminc_ore::target::I32) -> bool {
        true
    }
}

fn main() {}
