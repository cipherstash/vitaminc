use vitaminc_aead_value::{Value, ValueKind};

#[test]
#[allow(deprecated)]
fn deprecated_alias_uses_the_same_value_model() {
    use vitaminc_aead_value::FfiValue;

    let old: FfiValue = FfiValue::String("secret".into());
    let value: Value = old.clone();
    match (&value, &old) {
        (Value::String(copy), FfiValue::String(original)) => {
            assert_eq!(copy.risky_ref(), original.risky_ref());
            assert_ne!(copy.risky_ref().as_ptr(), original.risky_ref().as_ptr());
        }
        _ => panic!("alias changed the variant"),
    }
    assert_eq!(value.kind(), Some(ValueKind::String));
    assert!(matches!(FfiValue::Null, Value::Null));
}

#[test]
fn kind_inventory_does_not_expose_its_length_in_the_type() {
    // A downstream caller can name the inventory's type independently of
    // the number of kinds this release provides.
    fn inventory() -> &'static [ValueKind] {
        ValueKind::ALL
    }

    for &kind in inventory() {
        assert_eq!(kind.name().parse::<ValueKind>(), Ok(kind));
    }
}
