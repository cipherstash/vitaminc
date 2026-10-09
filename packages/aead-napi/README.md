# vitaminc-aead-napi

NAPI (Node-API) bindings layer for the Vitamin-C AEAD encryption traits —
the JS-specific piece of exposing `vitaminc` encryption to Node.js.

The value tree itself lives in the language-neutral `vitaminc-aead-value`
crate ([`Value`]): an owned, `Send`, self-describing representation of a
dynamically typed value, with `Encrypt`/`Decrypt` impls and a frozen,
cross-language leaf wire format. This crate adds only what is JS-specific:

- **`NapiValue`** — a newtype over [`Value`] carrying the
  `FromNapiValue`/`ToNapiValue` conversions (the orphan rule prevents
  implementing napi's traits on the foreign type directly). Conversions run
  on the JS thread; everything past the `#[napi]` boundary works with the
  bare `Value`, on any thread.
  - JS `number` ↔ `Value::Float64` (always — integral JS numbers stay
    numbers). JS `BigInt` carries integer typing: fits `i64` →
    `Value::Int64`, above `i64::MAX` but fits `u64` → `Value::UInt64`,
    larger → rejected. JS has no 32-bit numeric types, so it never encodes
    `Int32`/`UInt32`/`Float32`. On decode: `Float32` widens exactly to a JS
    `number` (`f64::from(f32)`); `Float64` is a `number`; `Int32`/`UInt32`
    are always a `number` (magnitude ≤ 2⁵³); `Int64`/`UInt64` yield a JS
    `number` within `Number.MAX_SAFE_INTEGER` and a `BigInt` beyond it.
- **`JsCipherText<Leaf, P>`** — projects the generic `CipherText` container
  onto plain JS values (`{ t, v }` nodes with `Buffer` leaves) and back, as
  an in-memory/application-side representation. Durable cross-language
  database storage is the EQL layer's job, not this projection's.

This crate is a library consumed by the Node addon (cdylib/npm package);
it is not itself loadable from Node.

## Testing the conversion layer

The `Encrypt`/`Decrypt` impls and the value tree are covered by ordinary Rust
unit tests. A live Node test converts a sample for every `ValueKind::ALL`
entry through `NapiValue::to_napi_value` and checks its JavaScript value.
Adding a kind without a sample or a working output conversion fails CI.
It also covers `Null`, `Undefined`, and `Passthrough`, which have no kind.

Run the same test locally (use `.dylib` instead of `.so` on macOS):

```sh
cargo build --locked -p vitaminc-aead-napi --example kind_inventory
node packages/aead-napi/tests/kind_inventory.cjs target/debug/examples/libkind_inventory.so
```

The JS-boundary conversion functions — `js_to_value`,
`value_to_js`, `node_to_js`, `node_from_js` — and their helpers —
`own_enumerable_keys`, `get_property_unknown`, `ensure_plain_object`,
`define_own_property` — are
not covered by the Rust unit tests: each takes a live `napi_env`, `Unknown`, or `Object`,
which only exists inside a running V8 isolate. The `napi/noop` dev feature
disables automatic addon registration, and `dyn-symbols` loads Node-API
symbols when the test addon runs in Node. Neither supplies a Node environment
to Rust unit tests. These functions remain exempted in `.cargo-crap.toml` and
`.cargo/mutants.toml`, by name rather than by file so the rest of those
modules stays gated.

The kind inventory test covers the output mapping and basic recursive
conversion. Input conversion, ciphertext conversion, and boundary rejection
cases still need JS-level tests driving a built addon; review changes to
those paths by hand until that coverage lands.

## Safety notes

- The original copies of encrypted values in the V8 heap are owned by the
  JS engine and cannot be wiped from Rust.
- Property names that would touch the prototype chain (`__proto__`,
  `constructor`, `prototype`) are rejected in both directions, and
  recursion depth is bounded.
- Only **plain objects** (prototype `Object.prototype` or `null`) are
  accepted for encryption. `Map`, `Set`, `RegExp`, `DataView`, class
  instances and other exotic objects keep their state in internal slots and
  would silently encrypt as `{}` — they are rejected with an error instead.
- Object enumeration reads **own, enumerable, string-keyed** properties
  only, so a polluted `Object.prototype` (or inherited enumerable getters)
  can never leak keys into — or run code during — encryption. An own
  property explicitly set to `undefined` round-trips.
- Sparse arrays (`[, , "x"]`, `new Array(n)`) are rejected; `[undefined]`
  is not sparse and round-trips. A hole is detected per index via
  `Object.hasOwn` semantics, so a polluted `Array.prototype` cannot fill
  holes with inherited elements.
- JS-reported array lengths are never trusted for up-front allocation
  (a `new Array(2**32 - 1)` costs the attacker one line and materialises
  nothing), in both the value converter and the ciphertext rebuilder.
- Strings containing unpaired UTF-16 surrogates are **rejected** rather
  than silently normalized: the UTF-8 fetch would replace a lone surrogate
  with U+FFFD, sealing a plaintext that no longer equals what the caller
  passed.
- Decrypted objects (and rebuilt ciphertext maps) are written with
  **own-property defines** (`napi_define_properties`), not `[[Set]]`
  assignment, so a polluted `Object.prototype` setter can never observe
  decrypted plaintext or swallow a property.
- Errors carry no cryptographic detail (`Unspecified` at the trait layer).

[`Value`]: vitaminc_aead_value::Value
