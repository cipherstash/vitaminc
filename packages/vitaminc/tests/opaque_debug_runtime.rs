#![allow(dead_code)]
// Verify that generated code does not trigger unused_results
#![deny(unused_results)]
use vitaminc::protected::OpaqueDebug;
use vitaminc_protected::Redacted;

#[test]
fn no_plaintext_leak_in_debug() {
    #[derive(OpaqueDebug)]
    struct S {
        secret: String,
    }

    let s = S {
        secret: "do-not-leak".into(),
    };
    let out = format!("{s:?}");
    assert!(!out.contains("do-not-leak"));
    assert!(out.contains("***"));
}

#[test]
fn struct_named_fields_are_masked() {
    #[derive(OpaqueDebug)]
    struct Credentials {
        user: String,
        pass: String,
    }

    let c = Credentials {
        user: "u".into(),
        pass: "p".into(),
    };
    let out = format!("{c:?}");
    let tn = core::any::type_name::<Credentials>();

    assert!(
        out == format!("{tn} {{ user: \"***\", pass: \"***\" }}")
            || out == format!("{tn} {{ pass: \"***\", user: \"***\" }}"),
        "got: {out}"
    );
}

#[test]
fn struct_tuple_fields_are_masked() {
    #[derive(OpaqueDebug)]
    struct Blob(u8, u16, u32);

    let out = format!("{:?}", Blob(1, 2, 3));
    let tn = core::any::type_name::<Blob>();
    assert_eq!(out, format!("{tn}(\"***\", \"***\", \"***\")"));
}

#[test]
fn struct_unit_prints_type_name_only() {
    #[derive(OpaqueDebug)]
    struct Marker;

    let out = format!("{Marker:?}");
    assert_eq!(out, core::any::type_name::<Marker>());
}

#[test]
fn enum_variants_masked() {
    #[derive(OpaqueDebug)]
    enum SecretThing {
        A(u32),
        B { x: u8, y: u8 },
        C,
    }

    let tn = core::any::type_name::<SecretThing>();

    let a = SecretThing::A(42);
    assert_eq!(format!("{a:?}"), format!("{tn}::A(\"***\")"));

    let b = SecretThing::B { x: 7, y: 9 };
    assert!(
        format!("{b:?}") == format!("{tn}::B {{x: \"***\", y: \"***\"}}")
            || format!("{b:?}") == format!("{tn}::B {{y: \"***\", x: \"***\"}}")
    );

    let c = SecretThing::C;
    assert_eq!(format!("{c:?}"), format!("{tn}::C"));
}

#[test]
fn generics_and_const_generics_show_in_type_name() {
    #[derive(OpaqueDebug)]
    struct Wrapper<T>(T);

    #[derive(OpaqueDebug)]
    struct Key<const N: usize>([u8; N]);

    let w = Wrapper(Key::<32>([0u8; 32]));
    let out = format!("{w:?}");

    assert!(out.starts_with("")); // cheap guard
    assert!(out.contains("Wrapper"));
    assert!(out.contains("Key"));
    assert!(out.contains("32"));
}

#[test]
fn custom_mask_attribute_is_used() {
    #[derive(OpaqueDebug)]
    #[opaque_debug(mask = "██")]
    struct Token(String);

    let out = format!("{:?}", Token("x".into()));
    let tn = core::any::type_name::<Token>();
    assert_eq!(out, format!("{tn}(\"██\")"));
}

#[test]
fn non_sensitive_attr_skips_masking() {
    #[derive(OpaqueDebug)]
    struct HasNonSensitiveField {
        sensitive: String,

        #[non_sensitive]
        value: String,
    }

    let out = format!(
        "{:?}",
        HasNonSensitiveField {
            sensitive: "do-not-print".into(),
            value: "ok-to-print".into(),
        }
    );
    assert_eq!(out, format!("opaque_debug_runtime::non_sensitive_attr_skips_masking::HasNonSensitiveField {{ sensitive: \"***\", value: \"ok-to-print\" }}"));
}

#[test]
fn non_sensitive_attr_fails_to_skip_if_type_is_redacted() {
    #[derive(OpaqueDebug)]
    struct HasNonSensitiveField {
        sensitive: String,

        #[non_sensitive]
        value: Redacted<String>,
    }

    let out = format!(
        "{:?}",
        HasNonSensitiveField {
            sensitive: "do-not-print".into(),
            value: Redacted::new("ok-to-print".into()),
        }
    );
    assert_eq!(out, format!("opaque_debug_runtime::non_sensitive_attr_fails_to_skip_if_type_is_redacted::HasNonSensitiveField {{ sensitive: \"***\", value: Redacted<alloc::string::String ***> }}"));
}

#[test]
fn non_sensitive_enum_variant_skips_masking() {
    #[derive(OpaqueDebug)]
    enum HasNonSensitiveField {
        Sensitive(String),
        #[non_sensitive]
        Value(String),
    }

    let sensitive = HasNonSensitiveField::Sensitive("do-not-print".into());
    let non_sensitive = HasNonSensitiveField::Value("ok-to-print".into());
    assert_eq!(format!("{sensitive:?}"), "opaque_debug_runtime::non_sensitive_enum_variant_skips_masking::HasNonSensitiveField::Sensitive(\"***\")");
    assert_eq!(format!("{non_sensitive:?}"), "opaque_debug_runtime::non_sensitive_enum_variant_skips_masking::HasNonSensitiveField::Value(\"ok-to-print\")");
}

#[test]
fn non_sensitive_tuple_struct_field() {
    #[derive(OpaqueDebug)]
    struct HasNonSensitiveField(String, #[non_sensitive] String);

    let out = format!(
        "{:?}",
        HasNonSensitiveField("do-not-print".into(), "ok-to-print".into())
    );
    assert_eq!(out, "opaque_debug_runtime::non_sensitive_tuple_struct_field::HasNonSensitiveField(\"***\", \"ok-to-print\")");
}
