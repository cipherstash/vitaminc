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

use napi::bindgen_prelude::{Array, Buffer, FromNapiValue, Object, ToNapiValue, Unknown};
use napi::{sys, Env, Error, Result, Status, ValueType};
use vitaminc_aead::CipherText;

use crate::convert::{
    define_own_property, eager_capacity, forbidden_key, get_property_unknown, own_enumerable_keys,
    MAX_DEPTH,
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
/// `From<Vec<u8>>` in); the passthrough payload `P` uses its own NAPI
/// conversions. For a cipher whose passthrough payload type is not itself
/// NAPI-convertible (e.g. the Rust-native `Box<dyn Any + Send>`), re-home
/// the tree first with [`CipherText::map_passthrough`].
pub struct JsCipherText<Leaf, P>(pub CipherText<Leaf, P>);

fn shape_error() -> Error {
    Error::new(Status::InvalidArg, "malformed ciphertext value")
}

fn node_to_js<Leaf, P>(env: sys::napi_env, node: CipherText<Leaf, P>) -> Result<sys::napi_value>
where
    Leaf: AsRef<[u8]>,
    P: ToNapiValue,
{
    let raw_env = Env::from_raw(env);
    let mut obj = Object::new(&raw_env)?;
    match node {
        CipherText::Single(leaf) => {
            obj.set(T_KEY, T_CIPHERTEXT)?;
            obj.set(V_KEY, Buffer::from(leaf.as_ref().to_vec()))?;
        }
        CipherText::None(leaf) => {
            obj.set(T_KEY, T_NONE)?;
            obj.set(V_KEY, Buffer::from(leaf.as_ref().to_vec()))?;
        }
        CipherText::EmptySequence(leaf) => {
            obj.set(T_KEY, T_EMPTY_SEQ)?;
            obj.set(V_KEY, Buffer::from(leaf.as_ref().to_vec()))?;
        }
        CipherText::EmptyMap(leaf) => {
            obj.set(T_KEY, T_EMPTY_MAP)?;
            obj.set(V_KEY, Buffer::from(leaf.as_ref().to_vec()))?;
        }
        CipherText::Sequence(items) => {
            obj.set(T_KEY, T_SEQ)?;
            let mut arr = raw_env.create_array(items.len() as u32)?;
            for (i, item) in items.into_iter().enumerate() {
                arr.set(i as u32, NodeHandle(item))?;
            }
            obj.set(V_KEY, arr)?;
        }
        CipherText::Map(entries) => {
            obj.set(T_KEY, T_MAP)?;
            let map = Object::new(&raw_env)?;
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
                // Own-property define, not `[[Set]]`: these keys are
                // attacker-writable, so a polluted inherited setter must
                // never run — see `convert::define_own_property`.
                let js_value = node_to_js(env, value)?;
                define_own_property(&map, &key, js_value)?;
            }
            obj.set(V_KEY, map)?;
        }
        CipherText::Passthrough(p) => {
            obj.set(T_KEY, T_PASSTHROUGH)?;
            obj.set(V_KEY, PassthroughHandle(p))?;
        }
    }
    unsafe { Object::to_napi_value(env, obj) }
}

const T_KEY: &str = "t";
const V_KEY: &str = "v";

/// Recursion helper so nested nodes can be assigned through `ToNapiValue`.
struct NodeHandle<Leaf, P>(CipherText<Leaf, P>);

impl<Leaf, P> ToNapiValue for NodeHandle<Leaf, P>
where
    Leaf: AsRef<[u8]>,
    P: ToNapiValue,
{
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
        node_to_js(env, val.0)
    }
}

/// Recursion helper for the passthrough payload.
struct PassthroughHandle<P>(P);

impl<P: ToNapiValue> ToNapiValue for PassthroughHandle<P> {
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
        unsafe { P::to_napi_value(env, val.0) }
    }
}

impl<Leaf, P> ToNapiValue for JsCipherText<Leaf, P>
where
    Leaf: AsRef<[u8]>,
    P: ToNapiValue,
{
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
        node_to_js(env, val.0)
    }
}

fn node_from_js<Leaf, P>(obj: &Object<'_>, depth: usize) -> Result<CipherText<Leaf, P>>
where
    Leaf: From<Vec<u8>>,
    P: FromNapiValue,
{
    if depth > MAX_DEPTH {
        return Err(Error::new(
            Status::InvalidArg,
            "ciphertext is nested too deeply",
        ));
    }
    let t: String = obj.get(T_KEY)?.ok_or_else(shape_error)?;
    match t.as_str() {
        T_CIPHERTEXT | T_NONE | T_EMPTY_SEQ | T_EMPTY_MAP => {
            let buf: Buffer = obj.get(V_KEY)?.ok_or_else(shape_error)?;
            let leaf = Leaf::from(buf.to_vec());
            Ok(match t.as_str() {
                T_CIPHERTEXT => CipherText::Single(leaf),
                T_NONE => CipherText::None(leaf),
                T_EMPTY_SEQ => CipherText::EmptySequence(leaf),
                _ => CipherText::EmptyMap(leaf),
            })
        }
        T_SEQ => {
            let arr: Array = obj.get(V_KEY)?.ok_or_else(shape_error)?;
            let len = arr.len();
            // Capacity is granted lazily: the reported length is
            // attacker-cheap (`{t:"seq", v:new Array(2**32-1)}` materialises
            // nothing), so reserving it up front would abort the process on
            // allocation failure before any element is validated.
            let mut items = Vec::with_capacity(eager_capacity(len));
            for i in 0..len {
                // `Array::get` maps only out-of-range indices to `None`; a
                // hole comes back as `undefined`, which is not a node
                // object — check the type before treating it as one.
                let element = arr.get::<Unknown>(i)?.ok_or_else(shape_error)?;
                if element.get_type()? != ValueType::Object {
                    return Err(shape_error());
                }
                let element = Object::from_unknown(element)?;
                items.push(node_from_js(&element, depth + 1)?);
            }
            Ok(CipherText::Sequence(items))
        }
        T_MAP => {
            let map: Object = obj.get(V_KEY)?.ok_or_else(shape_error)?;
            // Own keys only — `Object::keys` walks the prototype chain, so
            // a hostile node object with enumerable prototype members would
            // otherwise have its inherited keys become ciphertext map
            // entries (see `own_enumerable_keys`).
            let keys = own_enumerable_keys(&map)?;
            let mut entries = Vec::with_capacity(keys.len());
            for key in keys {
                if forbidden_key(&key) {
                    return Err(Error::new(
                        Status::InvalidArg,
                        format!("ciphertext map key is not allowed: {key}"),
                    ));
                }
                let value: Object = map.get(&key)?.ok_or_else(shape_error)?;
                entries.push((key, node_from_js(&value, depth + 1)?));
            }
            Ok(CipherText::Map(entries))
        }
        T_PASSTHROUGH => {
            // Raw fetch, not `obj.get` — `undefined` is a *faithful*
            // projection here (`P = ()` and `NapiValue::Undefined` both
            // project to it, and `JSON.stringify` drops the key outright),
            // and `Object::get` would map it to `None` and reject the
            // crate's own output as malformed. Whether `undefined`
            // converts is `P`'s decision.
            let value = get_property_unknown(obj, V_KEY)?;
            let p = P::from_unknown(value)?;
            Ok(CipherText::Passthrough(p))
        }
        _ => Err(shape_error()),
    }
}

impl<Leaf, P> FromNapiValue for JsCipherText<Leaf, P>
where
    Leaf: From<Vec<u8>>,
    P: FromNapiValue,
{
    unsafe fn from_napi_value(env: sys::napi_env, napi_val: sys::napi_value) -> Result<Self> {
        let obj = unsafe { Object::from_napi_value(env, napi_val) }?;
        Ok(JsCipherText(node_from_js(&obj, 0)?))
    }
}
