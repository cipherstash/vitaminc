
## [0.8.0] - 2026-10-21

A ciphertext holding a typed null (`vitaminc-aead` 0.8.0) decrypts to JavaScript's `null`, whatever the type of the absent value.

### Not guaranteed

- JavaScript has no type for an absent value, so a `null` sealed from JavaScript is still the one-byte null, and the ciphertext's length still shows that the value is absent.

## [0.7.0] - 2026-10-20

## [0.6.1] - 2026-10-18

## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** the crate now declares a minimum supported Rust version of 1.88. 0.5.1 declared none.
- **Breaking:** `NapiValue` and the `FfiValue` re-export are gone, because `vitaminc-aead-value` is gone. An addon now encrypts a live JavaScript value with `encrypt(JsRef::new(value), &cipher, aad)` and decrypts with `decrypt_into(&cipher, ct, aad, JsBuilder::new(&env))`. No Rust value tree is built in between. To encrypt off the JavaScript thread, take `JsRef::to_frame()` on that thread and seal the frame on the worker; `JsBuilder::build(&env, frame)` turns a frame back into a JavaScript value.
- **Breaking:** an encryption that fails inside the walk (a getter that throws, an unpaired surrogate, an out-of-range `BigInt`) now arrives through the error's `source` as a `JsFault`. Call `JsFault::from_source` at the boundary to turn it back into the napi error, so the application sees the exception its getter threw.
- **Breaking:** every integer now decrypts to a JavaScript `BigInt`, at every width. In 0.5.1 an integer within `Number.MAX_SAFE_INTEGER` came back as a `number`. Code that does arithmetic or `===` against a `number` on decrypted integers must handle `BigInt`.
- **Breaking:** a `BigInt` now encrypts at the narrowest integer width that holds it (`5n` is an `i8`), up to 128 bits, instead of always `Int64` or `UInt64`. A `BigInt` outside the 128-bit range is refused. Equality terms from `vitaminc-prf`'s new `normalize` feature match across integer widths, so this does not split matches there. A JS `number` is still always a float and never matches an integer's term, so use `BigInt` for integer data.
- **Breaking:** `JsCipherText<Leaf, P>` now needs `P: NapiPassthrough` instead of napi-rs's `ToNapiValue` and `FromNapiValue`. `NapiPassthrough` is implemented for `PassthroughFrame` and `()`. A `{ t: "none" }` node is now malformed, because the `none` ciphertext node no longer exists. JavaScript values never produced one; only a Rust `Option::None` did.
- **Breaking:** 0.6.0 seals leaves as wire version 2. Ciphertexts written by 0.5.1 through `NapiValue` are version 1 leaves. They still decrypt, but only through `vitaminc-encrypt`'s `Aes256Cipher::opening_version_1()`: a plain `Aes256Cipher` refuses them. Their `{ t, v }` shape is unchanged.

### Security

- Decrypted array elements, and a ciphertext node's `t`, `v` and sequence elements, are now written as own properties. In 0.5.1 they were assigned with `[[Set]]`, so a setter planted on `Array.prototype` or `Object.prototype` received the decrypted plaintext or the ciphertext, and the result lost the property.
- Every property read now checks, just before the read, that the property is the object's own. In 0.5.1 a ciphertext node missing its own `t` or `v`, or a hole in a sequence, took the value from a possibly polluted prototype. A getter that deleted a later key while the walk ran could also make that later read fall through to the prototype. These now fail as malformed input; an own `v: undefined` is still accepted.
- A primitive passed as a ciphertext node is refused. In 0.5.1 N-API read its `t` and `v` through its prototype, such as `String.prototype`.
- An object key with an unpaired surrogate is refused, as a string value already was. In 0.5.1 the key was read as U+FFFD, the lookup missed, and the value was sealed as `undefined`.
- Building JavaScript from a Rust value now has the same 128-level depth limit as reading it, and a passthrough payload continues the count instead of restarting it. A tree past the limit is measured and dropped without recursion. In 0.5.1 a deep enough tree could overflow the stack and abort Node.
- Every copy Rust makes of incoming text is now wiped on drop: the UTF-16 code units and the UTF-8 text of each value, key and wrapper. In 0.5.1 the UTF-16 copy and the object keys were not wiped. Not guaranteed: an error message can name a key, and on the way out the Rust copies of decrypted text, keys and bytes are not wiped. The JavaScript engine's own copies can never be wiped from Rust.

### Features

- JavaScript `Date` values now encrypt, as a millisecond timestamp, and decrypt to a `Date` with the same count. 0.5.1 refused them.
- The wrapper classes `VcDate`, `VcTimestamp`, `VcDecimal` and `VcUuid` carry a calendar date, a nanosecond timestamp, an exact decimal and a UUID. An addon exports them with `Wrappers::exports`. They live in the crate's own per-environment registry, so the addon's instance data stays free. The classes and their instances are frozen, so prototype pollution cannot alter them. Decryption returns a `Date` for a whole-millisecond timestamp and a `VcTimestamp` otherwise. Timestamps outside years 0000–9999 use the ISO 8601 expanded year. A leap second is refused.
- A scalar that cannot be converted throws a `TypeError` with a stable code (`ConversionError::code`): `ERR_INTEGER_RANGE`, `ERR_INVALID_DATE`, `ERR_INVALID_TIMESTAMP`, `ERR_INVALID_DECIMAL`, `ERR_NON_FINITE_DECIMAL` or `ERR_INVALID_UUID`.
- A value with a logical type this build does not know is refused on decryption, instead of being returned with its type dropped.
- `MAX_DEPTH` (128) is now public.

### Fixes

- Typed arrays other than `Uint8Array` and `Buffer`, and `DataView`, are refused. In 0.5.1 they could be sealed as their raw bytes.
- A `Proxy` over a `Map`, `Date` or other exotic object is refused, because the prototype check now runs the proxy's `getPrototypeOf` trap. A proxy over a plain object still encrypts through its traps.
- A refused typed array, or a ciphertext leaf that is not a `Buffer`, no longer stays referenced until the environment exits.

## [0.5.1] - 2026-10-05

## [0.5.0] - 2026-09-20

## [0.4.0] - 2026-09-12

## [0.3.0] - 2026-09-07

## [0.2.0] - 2026-09-03

First release.

### Features

- Node.js FFI bridge: encrypt and decrypt JS values (null, undefined, booleans, numbers, strings, bytes, arrays, objects) through the `vitaminc-aead-value` tree, with unencrypted subtrees carried via passthrough.
- The JS boundary is hardened: prototype-chain keys (`__proto__`, `constructor`, `prototype`) are rejected in both directions, exotic objects are refused, and allocation limits apply.
