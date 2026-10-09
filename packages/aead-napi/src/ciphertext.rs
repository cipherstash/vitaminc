//! Projection of the generic [`CipherText`] container onto JS structures.
//!
//! The container has **no canonical byte representation** — only the sealed
//! `Leaf` type does (see the container docs). Crossing the FFI boundary, the
//! tree is projected onto plain JS values that the application can hold,
//! store (e.g. as JSONB with its own Buffer encoding policy), and pass back
//! for decryption:
//!
//! ```text
//! Single(leaf)        ↦ { t: "ct",   v: Buffer }
//! None(leaf)          ↦ { t: "none", v: Buffer }
//! Sequence(...)       ↦ { t: "seq",  v: [node, ...] }
//! EmptySequence(leaf) ↦ { t: "eseq", v: Buffer }
//! Map(entries)        ↦ { t: "map",  v: { key: node, ... } }
//! EmptyMap(leaf)      ↦ { t: "emap", v: Buffer }
//! Passthrough(p)      ↦ { t: "pt",   v: <P's own JS projection> }
//! ```
//!
//! The `t`/`v` node shape is an **in-memory/application-side convenience**:
//! it is what a JS application holds between `encrypt` and `decrypt` calls,
//! and what an application that manages its own storage may choose to
//! persist. Database interop across languages is *not* this projection's
//! job — that is the role of the EQL layer, which owns the durable
//! database format and treats the sealed leaves opaquely. Within that
//! scope the node shape should still change only deliberately (apps may
//! have persisted it), but it is not a cross-language wire commitment;
//! only the leaf byte format (see `vitaminc-aead-value`) is frozen.

use napi::bindgen_prelude::{
    Array, Buffer, FromNapiValue, JsObjectValue, JsValue, Object, ToNapiValue, Unknown,
};
use napi::{sys, Env, Error, Result, Status, ValueType};
use vitaminc_aead::CipherText;

use crate::convert::{
    define_own_properties, eager_capacity, forbidden_key, get_own, get_property_unknown, new_array,
    own_enumerable_keys, own_property, MAX_DEPTH,
};

const T_CIPHERTEXT: &str = "ct";
const T_NONE: &str = "none";
const T_SEQ: &str = "seq";
const T_EMPTY_SEQ: &str = "eseq";
const T_MAP: &str = "map";
const T_EMPTY_MAP: &str = "emap";
const T_PASSTHROUGH: &str = "pt";

/// Newtype carrying a [`CipherText`] across the NAPI boundary using the
/// node projection documented at the module level.
///
/// `Leaf` needs only byte-level accessors (`AsRef<[u8]>` out,
/// `From<Vec<u8>>` in); the passthrough payload `P` converts through
/// [`NapiPassthrough`]. For a cipher whose passthrough payload type is not
/// [`NapiValue`] or `()` (e.g. the Rust-native `Box<dyn Any + Send>`),
/// re-home the tree first with [`CipherText::map_passthrough`].
///
/// [`NapiValue`]: crate::NapiValue
pub struct JsCipherText<Leaf, P>(pub CipherText<Leaf, P>);

/// A ciphertext passthrough payload's conversion to and from JS.
///
/// Both directions take the depth the payload sits at, so a payload shares
/// the tree's 128-level nesting limit, as it does in the transport encoding,
/// rather than starting a fresh count.
pub trait NapiPassthrough: Sized {
    /// Build the payload's JS value at `depth`.
    fn to_js(self, env: &Env, depth: usize) -> Result<Unknown<'_>>;
    /// Read the payload from its JS value at `depth`.
    fn from_js(value: Unknown<'_>, depth: usize) -> Result<Self>;
}

/// No payload: projects to `undefined`, which is all it accepts back.
impl NapiPassthrough for () {
    fn to_js(self, env: &Env, _depth: usize) -> Result<Unknown<'_>> {
        ().into_unknown(env)
    }

    fn from_js(value: Unknown<'_>, _depth: usize) -> Result<Self> {
        // napi-rs's own `()` conversion accepts any value; check instead.
        if value.get_type()? == ValueType::Undefined {
            Ok(())
        } else {
            Err(shape_error())
        }
    }
}

fn depth_error() -> Error {
    Error::new(Status::InvalidArg, "ciphertext is nested too deeply")
}

fn shape_error() -> Error {
    Error::new(Status::InvalidArg, "malformed ciphertext value")
}

fn node_to_js<Leaf, P>(env: &Env, node: CipherText<Leaf, P>, depth: usize) -> Result<Object<'_>>
where
    Leaf: AsRef<[u8]>,
    P: NapiPassthrough,
{
    if depth > MAX_DEPTH {
        return Err(depth_error());
    }
    let leaf = |tag: &'static str, leaf: Leaf| -> Result<(&'static str, Unknown<'_>)> {
        Ok((tag, Buffer::from(leaf.as_ref().to_vec()).into_unknown(env)?))
    };
    let (tag, value) = match node {
        CipherText::Single(l) => leaf(T_CIPHERTEXT, l)?,
        CipherText::None(l) => leaf(T_NONE, l)?,
        CipherText::EmptySequence(l) => leaf(T_EMPTY_SEQ, l)?,
        CipherText::EmptyMap(l) => leaf(T_EMPTY_MAP, l)?,
        CipherText::Sequence(items) => {
            let mut arr = new_array(env, items.len())?;
            let mut elements = Vec::with_capacity(items.len());
            for (i, item) in items.into_iter().enumerate() {
                let node = node_to_js(env, item, depth + 1)?;
                elements.push(own_property(env, &i.to_string(), &node)?);
            }
            define_own_properties(&mut arr, &elements)?;
            (T_SEQ, arr.into_unknown(env)?)
        }
        CipherText::Map(entries) => {
            let mut map = Object::new(env)?;
            let mut properties = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                // Map keys travel in the clear inside the stored ciphertext
                // and are therefore attacker-writable; never assign
                // prototype-polluting names onto a JS object.
                if forbidden_key(&key) {
                    return Err(Error::new(
                        Status::InvalidArg,
                        format!("ciphertext map key is not allowed: {key}"),
                    ));
                }
                let node = node_to_js(env, value, depth + 1)?;
                properties.push(own_property(env, &key, &node)?);
            }
            define_own_properties(&mut map, &properties)?;
            (T_MAP, map.into_unknown(env)?)
        }
        // The payload sits one level deeper, as the transport encoding counts it.
        CipherText::Passthrough(p) => (T_PASSTHROUGH, p.to_js(env, depth + 1)?),
    };
    // Own properties throughout, so a polluted inherited `t`, `v` or index
    // setter never sees the ciphertext (see `define_own_properties`).
    let mut obj = Object::new(env)?;
    let tag = tag.into_unknown(env)?;
    define_own_properties(
        &mut obj,
        &[
            own_property(env, T_KEY, &tag)?,
            own_property(env, V_KEY, &value)?,
        ],
    )?;
    Ok(obj)
}

const T_KEY: &str = "t";
const V_KEY: &str = "v";

impl<Leaf, P> ToNapiValue for JsCipherText<Leaf, P>
where
    Leaf: AsRef<[u8]>,
    P: NapiPassthrough,
{
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
        Ok(node_to_js(&Env::from_raw(env), val.0, 0)?.raw())
    }
}

/// A node must be a JS object. napi-rs's `Object` conversion does not check
/// the type, and N-API reads properties of a primitive through its wrapper
/// object, so a bare string would otherwise read `t` and `v` from a
/// (possibly polluted) `String.prototype`.
fn node_object(value: Unknown<'_>) -> Result<Object<'_>> {
    if value.get_type()? != ValueType::Object {
        return Err(shape_error());
    }
    Object::from_unknown(value)
}

/// A node's own `t` or `v`. A node missing either would otherwise take it
/// from a (possibly polluted) prototype. Ownership is checked immediately
/// before the read, where no JS can run in between, so a getter on the
/// other field cannot delete this one after the check.
fn own_field<'e>(obj: &Object<'e>, key: &str) -> Result<Unknown<'e>> {
    if !obj.has_own_property(key)? {
        return Err(shape_error());
    }
    get_property_unknown(obj, key)
}

fn node_from_js<Leaf, P>(obj: &Object<'_>, depth: usize) -> Result<CipherText<Leaf, P>>
where
    Leaf: From<Vec<u8>>,
    P: NapiPassthrough,
{
    if depth > MAX_DEPTH {
        return Err(depth_error());
    }
    let t = String::from_unknown(own_field(obj, T_KEY)?)?;
    match t.as_str() {
        T_CIPHERTEXT | T_NONE | T_EMPTY_SEQ | T_EMPTY_MAP => {
            let buf = Buffer::from_unknown(own_field(obj, V_KEY)?)?;
            let leaf = Leaf::from(buf.to_vec());
            Ok(match t.as_str() {
                T_CIPHERTEXT => CipherText::Single(leaf),
                T_NONE => CipherText::None(leaf),
                T_EMPTY_SEQ => CipherText::EmptySequence(leaf),
                _ => CipherText::EmptyMap(leaf),
            })
        }
        T_SEQ => {
            let arr = Array::from_unknown(own_field(obj, V_KEY)?)?;
            // The same array seen as an object, for per-index own checks.
            let elements = Object::from_unknown(arr.to_unknown())?;
            let len = arr.len();
            // Capacity is granted lazily: the reported length is
            // attacker-cheap (`{t:"seq", v:new Array(2**32-1)}` materialises
            // nothing), so reserving it up front would abort the process on
            // allocation failure before any element is validated.
            let mut items = Vec::with_capacity(eager_capacity(len));
            for i in 0..len {
                // Own elements only: a hole would otherwise read an element
                // from a (possibly polluted) `Array.prototype`, and as
                // `undefined` it is not a node anyway.
                if !elements.has_own_property(&i.to_string())? {
                    return Err(shape_error());
                }
                let element = arr.get::<Unknown>(i)?.ok_or_else(shape_error)?;
                items.push(node_from_js(&node_object(element)?, depth + 1)?);
            }
            Ok(CipherText::Sequence(items))
        }
        T_MAP => {
            let map = node_object(own_field(obj, V_KEY)?)?;
            // Own keys only — `Object::keys` walks the prototype chain, so
            // a hostile node object with enumerable prototype members would
            // otherwise have its inherited keys become ciphertext map
            // entries (see `own_enumerable_keys`).
            let keys = own_enumerable_keys(&map)?;
            let mut entries = Vec::with_capacity(keys.len());
            for key in keys {
                if forbidden_key(&key.name) {
                    return Err(Error::new(
                        Status::InvalidArg,
                        format!("ciphertext map key is not allowed: {}", key.name),
                    ));
                }
                let value = node_object(get_own(&map, &key)?)?;
                entries.push((key.name, node_from_js(&value, depth + 1)?));
            }
            Ok(CipherText::Map(entries))
        }
        T_PASSTHROUGH => {
            // `undefined` is a *faithful* projection here (`P = ()` and
            // `NapiValue::Undefined` both project to it), and
            // `JSON.stringify` drops a `v: undefined` key outright, so a
            // missing `v` reads as `undefined` rather than as malformed —
            // never from the prototype. Whether `undefined` converts is
            // `P`'s decision.
            let env = Env::from_raw(obj.value().env);
            let value = if obj.has_own_property(V_KEY)? {
                own_field(obj, V_KEY)?
            } else {
                ().into_unknown(&env)?
            };
            Ok(CipherText::Passthrough(P::from_js(value, depth + 1)?))
        }
        _ => Err(shape_error()),
    }
}

impl<Leaf, P> FromNapiValue for JsCipherText<Leaf, P>
where
    Leaf: From<Vec<u8>>,
    P: NapiPassthrough,
{
    unsafe fn from_napi_value(env: sys::napi_env, napi_val: sys::napi_value) -> Result<Self> {
        // SAFETY: napi-rs calls this with the `env` and `napi_val` of the
        // current call, which is all `Unknown::from_napi_value` needs: an
        // `Unknown` may hold any value type, and `node_object` checks it is
        // an object before anything reads it as one. The handle does not
        // outlive this call.
        let value = unsafe { Unknown::from_napi_value(env, napi_val) }?;
        let obj = node_object(value)?;
        Ok(JsCipherText(node_from_js(&obj, 0)?))
    }
}
