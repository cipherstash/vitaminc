// With `crate = "..."` the derives must use the given path verbatim and skip
// the manifest lookup. This package has no protected dependency, so the
// lookup would fail; it compiles only if the override is honoured. The
// stand-in module provides just the items the generated code names.
mod stand_in {
    pub trait OpaqueDebug {}

    #[derive(Clone, Copy)]
    pub struct Choice(u8);

    impl From<u8> for Choice {
        fn from(v: u8) -> Self {
            Choice(v)
        }
    }

    impl From<Choice> for bool {
        fn from(c: Choice) -> bool {
            c.0 == 1
        }
    }

    impl core::ops::BitAnd for Choice {
        type Output = Self;

        fn bitand(self, rhs: Self) -> Self {
            Choice(self.0 & rhs.0)
        }
    }

    pub trait TimingSafeEq {
        fn ts_eq(&self, other: &Self) -> Choice;
    }

    impl TimingSafeEq for u8 {
        fn ts_eq(&self, other: &Self) -> Choice {
            Choice((self == other) as u8)
        }
    }
}

#[derive(vitaminc_protected_derive::OpaqueDebug)]
#[opaque_debug(crate = "crate::stand_in")]
struct Token(u8);

#[derive(vitaminc_protected_derive::TimingSafeEq)]
#[timing_safe(crate = "crate::stand_in")]
struct Key(u8);

fn assert_marker<T: stand_in::OpaqueDebug>(_: &T) {}

fn main() {
    let token = Token(1);
    assert_marker(&token);
    assert!(format!("{token:?}").ends_with("Token(\"***\")"));
    assert!(Key(1) == Key(1));
    assert!(Key(1) != Key(2));
}
