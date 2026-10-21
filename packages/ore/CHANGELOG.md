
## [0.8.0] - 2026-10-21

### Breaking

- **Breaking:** seal a fixed-width None as a typed null as long as a Some, so ciphertext length no longer shows which values are absent
- **Breaking:** give every null an equality term so the index no longer shows which values were absent
- **Breaking:** let an order space place nulls first or last so ORDER BY with nulls can be answered from the index

### Documentation

- explain placing nulls first or last, what a placed null reveals, and how a range must skip the sentinel
- match the ADR to the shipped API and say what Reserved means in plain words
- say how terms of the two policies meet, and why a scheme cannot answer for every target

### Features

- make a marker space's null policy part of its type, so two policies' terms cannot meet

### Fixes

- refuse a null's term or query for a runtime target the scheme does not take
- read every byte when checking for the sentinel so the time does not depend on the value

## [0.7.0] - 2026-10-20

Order terms stored by 0.6 stay valid and compare with terms made by 0.7: the encodings, the domain labels and the salt do not change. The exceptions are the removed one-byte targets, and a scheme crate that added its own text and bytes marker byte, which it must now drop (see below).

### Breaking

- **Breaking:** A space's target is a type when it is known at compile time: `scheme.target(I32).context(ctx).encrypt(v)`, with one marker per target in `vitaminc_ore::target`. `encrypt` takes only a value that always fits (`FitsIn`), so `encrypt(42i64)` into an `I32` space no longer compiles, and it returns the scheme's own error. `scheme.encrypt(v)` uses the value's own target and the empty context. For a target chosen at runtime, pass an `OrderTarget` to `target(..)` and call `encrypt_checked`, which is 0.6's `encrypt`.
- **Breaking:** `OrderColumn` is renamed `OrderSpace`. `column(target, context)` and the `OrderColumn` alias stay, deprecated, for one release; on them, call `encrypt_checked` where you called `encrypt`.
- **Breaking:** Encryption returns an `OrderTerm` that carries its target, and `compare` takes two of them. Terms of two different marker targets cannot be compared, which is a compile error; under an `OrderTarget`, `compare` returns `None` for terms of different targets. Store `term.into_raw()`, and turn a term read back into the space's own with `space.term(raw)`.
- **Breaking:** The one-byte targets are gone: `OrderTarget::I8` and `U8`, their markers, and the `INT8` and `UINT8` domain labels. An order over 256 possible values gives the values away. An `i8` or `u8` still goes into `I16` or wider, but `scheme.encrypt(42i8)` does not compile: name a wider target, or use an equality index. Terms made under `I8` or `U8` do not compare with terms of a wider target, so an index built with them has to be re-encrypted.
- **Breaking:** For scheme authors, `OrderScheme` gains `type Space` and `open(&self, target, salt)`, which derives a space's keys once rather than once per term (about 20% of the cost of an `i64` term under block ORE). `encrypt_plaintext` takes the opened space instead of the salt, and returns `Self::Error` instead of `OrderError`. `open` may run more than once for one space, so it must be a pure derivation from the key, target and salt.
- **Breaking:** For scheme authors, `OrderScheme::Space` must be `ZeroizeOnDrop`, so a `Vec<u8>` of derived keys does not compile. Use `Protected`, a cipher that wipes itself on drop, or `()`.
- **Breaking:** For scheme authors, a scheme declares the targets it takes by implementing `Supports`, with `supports_targets!(Scheme; I16, ...)` or `supports_every_target!(Scheme)`. Naming an unsupported marker target does not compile, and an unsupported `OrderTarget` is refused with `OrderError::Unsupported` before the scheme is called. `OrderError::unsupported` is removed.
- **Breaking:** For scheme authors, text and bytes plaintexts now start with `VARIABLE_WIDTH_MARKER` (`0x01`), so an `OrderPlaintext` is never empty. An empty plaintext made a term that depended on neither the key nor the salt, so anyone could write a valid-looking term into any index. A scheme crate that already added this byte itself must stop doing so, or its text and bytes terms change.

### Features

- `OrderQuery`, the query side of an order scheme. Under block ORE a query is the left half of a term only, smaller and cheaper than a stored term. Make one with `space.encrypt_query(v)` or `encrypt_query_checked`, and order it against stored terms with `space.compare_query(&query, &term)`. A `QueryTerm` is labelled with its target and is a type of its own, so it cannot be compared where a term is expected, and its `Debug` masks its bytes. A scheme whose terms are their own queries, as the CLWW schemes' are, implements it with `Query = Term`.
- `OrderSpace::open` opens a space's scheme up front, so a scheme that cannot open reports it before any value is encrypted. Otherwise a space opens at its first value. Reuse a space across terms to get the per-space key derivation. A space is `Send` and `Sync` when the scheme and its `Space` are.
- A `test-support` feature with `test_support::conformance`, `query_conformance` and `static_target`, which a scheme crate runs against its real scheme. They fail a term that is the same under another key or context, an order the scheme does not keep, and a `Supports` impl that the runtime answer contradicts.

### Not guaranteed

- Do not persist or log a query. Beside the stored terms it orders every one of them against the searched value, and block ORE queries are deterministic, so two equal queries mean two searches for the same value. The type only keeps a query out of `compare`: its bytes are bytes, and written in a term's place they make every later `compare` under block ORE return `None`.
- A query is not wiped from memory. It is sent to the database, which sees it by design, and the process that made it already holds the value and the key.
- Text order terms are normalized through the `unicode-normalization` iterators, whose small internal buffers move to the heap as soon as a character's combining marks pass four code points, and are then freed without being wiped. This is outside this crate's control (#488).

### Fixes

- An integer's order encoding is written straight into the wiped buffer that is returned, so no unwiped copy is made. The encoded bytes do not change.

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
