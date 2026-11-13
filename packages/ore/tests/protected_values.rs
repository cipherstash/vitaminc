//! `vitaminc_aead`'s wipeable `Date`, `Decimal` and `Uuid` are `Orderable`,
//! and each orders exactly as the type it wraps: the same term, owned or
//! borrowed, through its own target or the target named.

mod common;

use core::str::FromStr;

use chrono::NaiveDate;
use common::Mock;
use vitaminc_ore::target::{Date, Decimal, Uuid};
use vitaminc_ore::{OrderEncrypt, OrderKeyInit};
use vitaminc_protected::Protected;

fn mock() -> Mock {
    Mock::new(Protected::new([3u8; 32]))
}

macro_rules! same_terms {
    ($target:expr, $wrapper:path, $($foreign:expr),+ $(,)?) => {{
        let mock = mock();
        $({
            let foreign = $foreign;
            let want = mock.encrypt(foreign).expect("encrypts");
            let owned = mock.encrypt(<$wrapper>::new(foreign)).expect("encrypts");
            let borrowed = mock.encrypt(&<$wrapper>::new(foreign)).expect("encrypts");
            let named = mock.target($target).encrypt(<$wrapper>::new(foreign)).expect("encrypts");
            assert_eq!(owned.as_ref(), want.as_ref());
            assert_eq!(borrowed.as_ref(), want.as_ref());
            assert_eq!(named.as_ref(), want.as_ref());
        })+
    }};
}

#[test]
fn a_date_orders_as_the_naive_date_it_holds() {
    same_terms!(
        Date,
        vitaminc_aead::Date,
        NaiveDate::MIN,
        NaiveDate::MAX,
        NaiveDate::from_ymd_opt(1969, 12, 31).expect("a date"),
        NaiveDate::from_ymd_opt(2026, 11, 14).expect("a date"),
    );
}

#[test]
fn a_decimal_orders_as_the_decimal_it_holds() {
    let dec = |text: &str| rust_decimal::Decimal::from_str(text).expect("a decimal");
    same_terms!(
        Decimal,
        vitaminc_aead::Decimal,
        dec("0"),
        dec("1.5"),
        dec("1.50"),
        dec("-1234.5678"),
        rust_decimal::Decimal::MAX,
        rust_decimal::Decimal::MIN,
    );
    // A decimal orders by value: `1.5` and `1.50` are one term.
    let mock = mock();
    assert_eq!(
        mock.encrypt(vitaminc_aead::Decimal::new(dec("1.5")))
            .expect("encrypts")
            .as_ref(),
        mock.encrypt(vitaminc_aead::Decimal::new(dec("1.50")))
            .expect("encrypts")
            .as_ref(),
    );
}

#[test]
fn a_uuid_orders_as_the_uuid_it_holds() {
    same_terms!(
        Uuid,
        vitaminc_aead::Uuid,
        uuid::Uuid::nil(),
        uuid::Uuid::max(),
        uuid::Uuid::from_u128(0x0123_4567_89ab_cdef),
    );
}
