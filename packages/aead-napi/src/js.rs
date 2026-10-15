//! What the walk and the build share about JavaScript objects: which keys
//! are read, how properties are written, and the limits both directions
//! apply. Everything here needs a live `Env`, so it runs on the
//! JavaScript thread.

use napi::bindgen_prelude::{
    FromNapiValue, JsObjectValue, JsValue, KeyCollectionMode, KeyConversion, KeyFilter, Object,
    ToNapiValue, Unknown, Utf16String,
};
use napi::{Env, Error, Property, Result, Status, ValueType};

/// Maximum nesting depth, in both directions: walking a JavaScript value
/// and building one. Bounds recursion so a deeply nested input cannot
/// overflow the stack. The same limit, counted the same way, as the
/// frame's, so any frame builds and any value that walks frames.
pub const MAX_DEPTH: usize = vitaminc_aead::frame::MAX_DEPTH;

/// Property names that must never be read from or written onto a plain JS
/// object: assigning them via `napi_set_property` triggers prototype-chain
/// semantics (prototype pollution), and accepting them on input would let a
/// value round-trip into that hazard.
pub(crate) fn forbidden_key(key: &str) -> bool {
    matches!(key, "__proto__" | "constructor" | "prototype")
}

pub(crate) fn depth_error() -> Error {
    Error::new(Status::InvalidArg, "value is nested too deeply")
}

pub(crate) fn forbidden_key_error(key: &str) -> Error {
    Error::new(
        Status::InvalidArg,
        format!("property name is not allowed: {key}"),
    )
}

/// Initial `Vec` capacity granted to a JS-reported length before any element
/// has been validated. An array's reported length is attacker-cheap —
/// `new Array(2**32 - 1)` materialises no elements — so reserving the full
/// reported length up front would let a one-line input demand hundreds of
/// gigabytes and abort the whole Node process on allocation failure
/// (`handle_alloc_error` is not a catchable JS throw). Real elements grow
/// the `Vec` amortised past this cap.
const MAX_EAGER_CAPACITY: usize = 1024;

pub(crate) fn eager_capacity(reported_len: u32) -> usize {
    (reported_len as usize).min(MAX_EAGER_CAPACITY)
}

/// An own property key: the JS key itself, for reading the property back
/// exactly, and its text.
pub(crate) struct OwnKey<'e> {
    handle: Unknown<'e>,
    pub(crate) name: String,
}

/// Own, enumerable, string-keyed properties of `obj`.
///
/// `Object::keys` (`napi_get_property_names`) walks the prototype chain —
/// per the Node-API spec it equals `napi_get_all_property_names` with
/// `include_prototypes | enumerable` — so a polluted `Object.prototype`
/// (or an instance with enumerable prototype members) would inject its
/// keys into the result, and inherited getters would run when the values
/// are read. Own-only enumeration forecloses both.
///
/// A key holding an unpaired surrogate is refused, as string values are: it
/// has no UTF-8 spelling, so it could not be sealed as written.
pub(crate) fn own_enumerable_keys<'e>(obj: &Object<'e>) -> Result<Vec<OwnKey<'e>>> {
    // napi-rs takes a single key filter, so symbol keys are skipped below
    // rather than by an `enumerable | skip_symbols` filter.
    let names = obj.get_all_property_names(
        KeyCollectionMode::OwnOnly,
        KeyFilter::Enumerable,
        KeyConversion::NumbersToStrings,
    )?;
    let len = names.get_array_length()?;
    let mut keys = Vec::with_capacity(eager_capacity(len));
    for i in 0..len {
        let handle = names.get_element::<Unknown>(i)?;
        if handle.get_type()? == ValueType::Symbol {
            continue;
        }
        let name = lossless_string(handle, "property name")?;
        keys.push(OwnKey { handle, name });
    }
    Ok(keys)
}

/// Read the own property `key` names, by the key's own JS handle.
///
/// The key list is a snapshot, and a getter that ran since may have deleted
/// this property; `[[Get]]` would then read it from a (possibly polluted)
/// prototype. So ownership is checked again immediately before the read,
/// where no JS can run in between for an ordinary object.
pub(crate) fn get_own<'e>(obj: &Object<'e>, key: &OwnKey<'e>) -> Result<Unknown<'e>> {
    if !obj.has_own_property_js(key.handle)? {
        return Err(Error::new(
            Status::InvalidArg,
            format!("property was removed while it was being read: {}", key.name),
        ));
    }
    obj.get_property_unchecked(key.handle)
}

/// A JS string as Rust text. Fetched as UTF-16 (JS's native representation)
/// and converted with `String::from_utf16`, which errors on unpaired
/// surrogates. The UTF-8 fetch (`napi_get_value_string_utf8`) would silently
/// replace them with U+FFFD, so a value would seal *mutated* and a key would
/// stop naming its property; refuse loudly instead.
pub(crate) fn lossless_string(value: Unknown<'_>, what: &str) -> Result<String> {
    let utf16 = Utf16String::from_unknown(value)?;
    String::from_utf16(&utf16).map_err(|_| {
        Error::new(
            Status::InvalidArg,
            format!("{what} contains an unpaired surrogate and cannot be encrypted losslessly"),
        )
    })
}

/// Fetch a property as the raw JS value, without [`Object::get`]'s
/// `undefined`-to-`None` mapping — `{ x: undefined }` has an own property
/// `x` (`Object.hasOwn` says so) and must round-trip, but `Object::get`
/// cannot distinguish its value from a missing property. A genuinely
/// missing property also comes back as `undefined`, which is exactly JS
/// property semantics.
pub(crate) fn get_property_unknown<'e>(obj: &Object<'e>, key: &str) -> Result<Unknown<'e>> {
    // The key goes over as a JS string with an explicit length, so a key
    // holding NUL survives (`get_named_property` would refuse it).
    let env = Env::from_raw(obj.value().env);
    let js_key = key.into_unknown(&env)?;
    obj.get_property_unchecked(js_key)
}

/// Whether `obj` is a plain object — prototype `Object.prototype` (compared
/// against a fresh `{}` from the same realm) or `null`
/// (`Object.create(null)`).
///
/// Anything else stores its state in internal slots or carries class
/// behaviour that key/value enumeration silently loses: a `Map`'s or
/// `Set`'s contents enumerate as `{}`, a `RegExp` drops its pattern and
/// flags, an `ArrayBuffer` or `DataView` its bytes. Encrypting such a
/// value would destroy the payload with no error at either end, so the
/// walk refuses it instead, once it has checked for the wrapper classes.
pub(crate) fn is_plain_object(obj: &Object<'_>) -> Result<bool> {
    let proto = obj.get_prototype()?;
    if proto.get_type()? == ValueType::Null {
        return Ok(true);
    }
    let env = Env::from_raw(obj.value().env);
    let baseline = Object::new(&env)?;
    let object_prototype = baseline.get_prototype()?;
    env.strict_equals(proto, object_prototype)
}

pub(crate) fn not_plain_error() -> Error {
    Error::new(
        Status::InvalidArg,
        "only plain objects and the wrapper classes can be encrypted; Map, Set, class instances \
         and other exotic objects lose their contents under key enumeration — convert the value \
         to a plain object, array, string, number, Buffer, or Uint8Array first",
    )
}

/// One own data property, for [`define_own_properties`]. `Property::new()`
/// defaults to writable, enumerable and configurable, the attributes
/// `obj.key = value` would give.
pub(crate) fn own_property<'e, V: JsValue<'e>>(
    env: &Env,
    key: &str,
    value: &V,
) -> Result<Property> {
    // A JS string name, not a UTF-8 C string, so a key holding NUL works.
    Ok(Property::new().with_name(env, key)?.with_value(value))
}

/// Write `properties` onto `obj` as **own data properties**
/// (`defineProperty` semantics) rather than through [`Object::set`] or
/// `Array::set` (`napi_set_property` / `napi_set_element`, `[[Set]]`
/// semantics), which walk the prototype chain: a polluted inherited setter on
/// a key or array index would receive the decrypted plaintext (leak) and
/// leave the result without the own property (drop). The intake side already
/// treats prototype pollution as in-threat-model (`own_enumerable_keys`,
/// `is_plain_object`); this closes the output side. One call per object.
pub(crate) fn define_own_properties(obj: &mut Object<'_>, properties: &[Property]) -> Result<()> {
    obj.define_properties(properties)
}

/// A new JS array of `len` holes, seen as an object so its elements can be
/// defined with [`define_own_properties`].
pub(crate) fn new_array<'e>(env: &'e Env, len: usize) -> Result<Object<'e>> {
    let len = u32::try_from(len)
        .map_err(|_| Error::new(Status::InvalidArg, "array is too long for JS"))?;
    Object::from_unknown(env.create_array(len)?.to_unknown())
}

#[cfg(test)]
mod tests {
    use super::{eager_capacity, forbidden_key, MAX_EAGER_CAPACITY};

    #[test]
    fn forbidden_keys_are_rejected() {
        assert!(forbidden_key("__proto__"));
        assert!(forbidden_key("constructor"));
        assert!(forbidden_key("prototype"));
        assert!(!forbidden_key("proto"));
        assert!(!forbidden_key("name"));
        assert!(!forbidden_key(""));
    }

    #[test]
    fn eager_capacity_passes_small_lengths_through() {
        assert_eq!(eager_capacity(0), 0);
        assert_eq!(eager_capacity(1), 1);
        assert_eq!(eager_capacity(37), 37);
        assert_eq!(
            eager_capacity(MAX_EAGER_CAPACITY as u32),
            MAX_EAGER_CAPACITY
        );
    }

    #[test]
    fn eager_capacity_caps_attacker_reported_lengths() {
        assert_eq!(
            eager_capacity(MAX_EAGER_CAPACITY as u32 + 1),
            MAX_EAGER_CAPACITY
        );
        assert_eq!(eager_capacity(u32::MAX), MAX_EAGER_CAPACITY);
    }
}
