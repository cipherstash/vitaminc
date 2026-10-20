
## [0.7.0] - 2026-10-20

### Breaking

- **Breaking:** typed targets and a chained API, with OrderColumn renamed to OrderSpace
- **Breaking:** start the text and bytes order encodings with a marker byte, so no order plaintext is empty
- **Breaking:** let a scheme derive its keys once per space, not once per term
- **Breaking:** open takes the space's target as well as its salt
- **Breaking:** require an order space to wipe itself on drop
- **Breaking:** remove the one-byte order targets, I8 and U8

### Documentation

- say what a query's type prevents and why not to keep one
- say a query is guarded against being kept, not wiped from memory
- say exactly when the normalization buffers move to the heap and what they leave behind

### Features

- OrderQuery, the query side of an order scheme

### Fixes

- mask a query's bytes in Debug, and test the query checks that had none
- write an integer's order encoding straight into the wiped buffer that is returned, so no plain copy is made

## [0.6.1] - 2026-10-18

## [0.6.0] - 2026-10-17

### Features

- First release. `vitaminc-ore` defines order terms for `vitaminc-aead`'s plaintext data model, the layer under order-revealing encryption schemes (block ORE in `ore-rs`, CLLW ORE and OPE in `cllw-ore`, which implement this crate's trait). For each orderable kind it fixes a frozen domain label (the `domain` module) and an order encoding whose byte order is the value's order, and seals it as an `OrderPlaintext` only this crate can build, so a scheme never sees bytes that skipped the encoding.
- Open a column with `scheme.column(target, context)` (from `OrderEncrypt`, which every `OrderScheme` gets and none can override), then `column.encrypt(value)`. The column's `OrderTarget` (`I8`..`U128`, `F64`, `Date`, `Timestamp`, `Decimal`, `Text`, `Bytes`, `Uuid`) decides the encoding: an integer of any width that fits goes in, and an `f32` widens to `f64`. A value that does not fit is refused with `NormalizeError::OutOfRange`, a value of another kind with `NormalizeError::Mismatch`, and one with no order term with `NormalizeError::NoDomain`. Values are never truncated.
- `order_terms(target, value)` collects one sealed term per orderable scalar with its path, refusing what encryption refuses. `Order(target)` runs the same walk beside other sinks, so one pass gives equality and order terms. `OrderColumn::encrypt_term` encrypts a collected term and refuses a term of another target.
- A scheme implements `OrderScheme::encrypt_plaintext` and `OrderScheme::compare`. Every scheme binds the same salt, `PAE("vitaminc/ore/v1", scheme, domain, context)`, derived once per column. `OrderKeyInit` keys a scheme from a protected array or runtime-length bytes.
- Order terms are not `Ord`. A term compares only with terms of the same scheme, key, target and context, through `OrderColumn::compare`, which returns `None` for terms it can tell were not made to compare. Keep a column's terms together.
- Text order terms fold case and accents (`École` sorts with `ecole`, `Straße` with `strasse`). Only marks with a non-zero canonical combining class are dropped, so Indic and Thai vowel signs are kept. Equality terms from `vitaminc-normalize` do not fold, so two strings can share an order position and still not be equal. A code point unassigned in Unicode 16 is refused. Text processing is variable-time.
- The data model types the API takes (`Physical`, `Logical`, `Raw`, `Int`, `Float`, `Encrypt` and others) are re-exported, so a scheme crate needs no direct `vitaminc-aead` dependency.
- A column reveals the combined leakage of every term it holds: order terms reveal order, and a column with equality terms too reveals both. Booleans, nulls and `undefined` have no order term. A scheme can refuse a target it cannot take (`OrderError::Unsupported`); the README lists which.
