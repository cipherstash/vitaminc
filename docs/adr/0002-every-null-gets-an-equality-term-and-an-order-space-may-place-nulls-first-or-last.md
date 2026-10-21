---
status: proposed
---

# Every null gets an equality term, and an order space may place nulls first or last

> **Proposed.** Closes item 5 of
> [cipherstash/vitaminc#493](https://github.com/cipherstash/vitaminc/issues/493),
> the one part of that issue the typed-null stack (#497, #499) left open.
> Numbered after ADR 0001 on `main`; other open stacks also claim 0002 and
> will be renumbered by whichever merges second, as before.

A sealed `None` is now as long as a sealed `Some` (#497), so the ciphertext
of an optional field no longer says whether the field was there. The index
terms beside it still do: a null has no equality term and no order term, so
the term column holds a SQL `NULL` exactly where the value was absent. That
undoes the typed null for any column with an index. This decision gives
every null an equality term, and lets an order space place nulls first or
last, so that an absent value is indexed like any other value and shows in
the index only as what any repeated value shows.

## Context

### What the terms reveal today

`vitaminc-normalize` gives a null no equality domain, and `vitaminc-ore`
gives one no order: both return `NoDomain`, the walk skips the scalar, and
an index layer stores nothing for it. Whoever reads the table reads the
null pattern of the column for free, with certainty, and without a key. The
typed null hid it in the ciphertext and the terms give it straight back.

### What an encrypted null reveals instead

An equality term is a keyed hash of the normalized value under a domain and
a context. If a null has one, every null in the space is one tied group, as
every repeated value is. The group's size is the null count, which is what
a repeated value's group size is too. Nothing says which tied group is the
nulls. That is strictly less than a SQL `NULL`, and in a column with many
repeated values it is much less.

An order term is different, because a null has to be placed. SQL places it
at one end (`NULLS FIRST` or `NULLS LAST`), and an index that answers
`ORDER BY` has to do the same, so the nulls are the tied group at one
extreme of the order. On top of that, both schemes in use leak the position
of the first difference between two terms: CLWW leaks the first differing
bit, and block ORE leaks the first differing byte through the left half of
its ciphertext, whose per-block tags and permuted symbols are deterministic
functions of the prefix. The vitaminc block ORE adapter stores the combined
left and right halves, so the left half is at rest in every row. In a
sparse domain, ages in an `I32` say, every value shares its top bytes with
every other value and the sentinel shares them with none, so the null group
is the one group that differs from everything at the top. In a dense domain
that tell fades, and the group is only the tied extreme.

So an encrypted null in an order index is identifiable by inference with
high confidence in most real columns. It is still never worse than the SQL
`NULL` it replaces, which needs no inference, and it is better in three
ways: the term column no longer carries a plaintext signal, the whole row
is handled one way whether the value is there or not, and when a scheme can
store terms that reveal nothing to each other
([cipherstash/ore.rs#99](https://github.com/cipherstash/ore.rs/issues/99),
right-only storage) the sentinel costs nothing at rest and only an observed
query exposes it. That last posture is where the design is heading, and
this encoding is ready for it.

### What was considered to hide the nulls further

Four ideas were worked through and set aside. They are recorded so they are
not re-derived.

**A marker byte in front of every order encoding** (`0x00` null-first,
`0x01` value, `0x02` null-last). It has exactly the leak above, made
certain rather than probable: a null and a value always differ at byte
zero and two values never do, under CLWW and under block ORE's left half
alike. It also makes every fixed width odd, so every scheme adapter's width
table changes, and the block ORE adapter names its widths one by one.

**A secret rotation of the code space per column**, so the order is cyclic
with a hidden cut and nulls land somewhere in the middle. It works
mechanically: a range that straddles the cut becomes two ranges, and
`ORDER BY` becomes a sort on "below the pivot" then the term. It hides the
nulls only when the cut falls inside the occupied range, which for a sparse
column means choosing the rotation from the data's distribution, and it
loses the index-order scan that top-k queries rely on. Every `ORDER BY` and
every straddling range query carries the pivot, and the pivot sits next to
the null group, so one observed query undoes it. It helps only a snapshot
adversary of combined ciphertexts, and the first-differing-byte leak still
shows the two clusters either side of the cut. Deferred to the
leakage-tuned domains, where the distribution is already a parameter.

**EncodeORE** (Liu, Lv, Li, Huang, Guo, Yuan and Dong, IEEE TDSC 2022):
encode the plaintext in scientific notation, an exponent part and a
left-aligned mantissa part, and apply CLWW to the encoding. Its leakage
function is CLWW's over the encoded value: the first differing bit of the
exponents when they differ, else of the mantissas. The gain is that a
differing bit no longer maps to a fixed magnitude, so two values with the
same exponent give nothing about their distance. A null sentinel is an
exponent no value has, so against nulls it leaks exactly what the plain
encoding leaks, at the exponent level: the tied extreme group that differs
from every value in the exponent's top bits. The one thing it would give
is spare exponent codes, so a sentinel need not displace an integer
maximum. Not worth a new encoding for every target.

**A trait on the scheme that says it can encode nulls securely.** The
honest distinction is not CLWW against block ORE: it is whether a scheme's
stored term can be compared against another stored term, and any scheme
that answers `ORDER BY` between rows must. No current scheme could
truthfully implement such a trait. The useful capability is the narrower
one, "stored terms are self-comparable", which block ORE can deny only
once right-only storage exists. That is recorded on ore.rs#99 and is not
part of this decision; until it exists, null ordering is an explicit
opt-in with the leakage written down.

### The three choices

For order there are three, mirroring SQL: do not index nulls at all (what
happens today), nulls first, or nulls last. For equality there is no
placement, so there is nothing to choose: the term exists.

## Decision

### 1. Every null has an equality term

`vitaminc-normalize` gives the null its own frozen domain and encoding:

| Kind | Domain | Bytes |
| --- | --- | --- |
| null, typed or plain | `vitaminc/prf/value/null/v1` | one byte, `0x00` |

`domain_of(None, Physical::Null)` returns it; `normalize` encodes it; the
`Terms` sink pushes a term for it like any scalar, at the null's path;
`typed_null` keeps forwarding to the plain null, because equality has no
width and the type adds nothing. There is no knob. A null in a text column
and a null in an integer column are the same term under the same key and
context, which is what SQL says too: `NULL IS NULL` whatever the column.
Spaces that must not tie already differ in context.

A boolean keeps `NoDomain`. Its two values are not a null's one, and the
reasoning in `OrderTarget`'s docs for refusing it stands.

Every caller that walks a value with an optional field now gets one more
term. A layer that wants to keep a SQL `NULL` for some column drops the
term it was handed; it knows the value was null because the term's domain
says so. Producing the term is the default because the secure path should
be the easy one, and dropping a term is an explicit act.

### 2. An order space may place nulls first or last

`vitaminc-ore` adds a null policy to a space:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NullOrder {
    /// Nulls sort below every value, as `NULLS FIRST`.
    First,
    /// Nulls sort above every value, as `NULLS LAST`.
    Last,
}

// A space with no policy, as today: a null has no term.
let space = scheme.context("users.age").target(I32);
// A space that places nulls.
let space = scheme.context("users.age").target(I32).nulls(NullOrder::Last);
// The normalizer for a walk, the same way.
let found = terms_by(Order::new(OrderTarget::I32).nulls(NullOrder::Last), &value)?;
```

The policy is fixed when the space is made, like the target and the
context, and every term of the space agrees with it. `OrderSpace::nulls`
and `Order::nulls` are the only way to set one. `OrderPlaintext` learns
`nulls() -> Option<NullOrder>`, and `order` takes the policy beside the
target.

Only a fixed-width target takes a policy. Text and bytes do not, for the
same reason the typed null itself stops at fixed widths: a sealed `None`
string is the plain null and already shows by its length, so placing it
in an order would hide nothing, and a variable-width column is not where
`ORDER BY` with nulls is asked for. On a marker target `nulls` compiles
only for the fixed-width markers; on `OrderTarget` it returns an error
for `Text` and `Bytes` rather than make a space every encryption refuses.

Without a policy nothing changes: a null, typed or plain, is `NoDomain`,
a walk skips it and `encrypt_checked` refuses it. With one, a null, typed
or plain, encodes to the space's sentinel, and `None::<T>` through the
`Encrypt::FIXED` path is the same sentinel. An `undefined` stays
`NoDomain` under every policy: it is not a value and not a null.

### 3. The sentinel is the extreme code of the target's own encoding

No new byte is added. Nulls-last takes the highest code the target's
width can hold, all `0xFF`, and nulls-first the lowest, all `0x00`. Where
a value already owns that code the integer and uuid encodings make room
in one direction only: under nulls-first every code moves up by one, so
the lowest code is free, and in both policies the one value refused is
the target's maximum. The float, date, timestamp and decimal encodings
have extreme codes no value reaches and move nothing.

| Target | Nulls first | Nulls last |
| --- | --- | --- |
| `I16`, `I32`, `I64`, `I128` | all `0x00`; every value's code is one higher than in the plain space; the signed maximum is refused | all `0xFF`; codes as in the plain space; the signed maximum is refused |
| `U16`, `U32`, `U64`, `U128` | all `0x00`; every value's code is one higher, so zero is `0x00…01`; the unsigned maximum is refused | all `0xFF`; codes as in the plain space; the unsigned maximum is refused |
| `Uuid` | all `0x00`; every uuid's bytes are one higher as a 128-bit number, so the nil uuid is `0x00…01`; the maximum uuid is refused | all `0xFF`; bytes as in the plain space; the maximum uuid is refused |
| `F64` | all `0x00`; no float encodes to it (it would be a non-canonical NaN) | all `0xFF`; no float encodes to it (same) |
| `Date` | all `0x00`; outside the admitted day range | all `0xFF`; outside the admitted day range |
| `Timestamp` | all `0x00`; the second is outside the admitted range | all `0xFF`; the second is outside the range and the sub-second field is impossible |
| `Decimal` | all `0x00`; the exponent field cannot reach 0 | all `0xFF`; the exponent field cannot reach 127 |
| `Text`, `Bytes` | no policy | no policy |

The shift exists so that zero is never refused. Without it a nulls-first
unsigned space could not hold zero, because all-zero bytes is how zero
encodes, and zero is the commonest value in a count or quantity column.
A signed space would have refused its minimum instead, since zero there
sits at the sign-flipped midpoint, and the nil uuid would have been
refused as well. Moving every code up by one under nulls-first trades all
of those for the maximum, which is the value nulls-last already gives up.
The shift costs one addition per value and nothing in leakage, and it
changes no stored byte of any existing space, because a policy space is a
new label (section 4).

The refusal is a new `NormalizeError::Reserved`, so a caller can tell
"this value is the sentinel of this space" from "this value does not fit
the target". The rule to document is one sentence: a column that places
nulls cannot hold its type's maximum. `i32::MAX` and `u32::MAX` are the
usual fake sentinels applications store for "unknown", so a column that
cannot hold both a real null and a fake one is a feature, and it is loud
at write time rather than silent at query time.

Four targets lose nothing: float, date, timestamp and decimal have extreme
codes no value reaches, which the implementation pins with a test against
each encoder's range.

This is chosen over the marker byte because the two leak the same thing
(see Context), and this one keeps every width and every scheme adapter
exactly as it is, and every stored byte of every value under nulls-last.
It is chosen over reworking the plain integer encodings because those are
frozen with stored data behind them; the shift touches only the new
nulls-first labels.

### 4. A policy is a new domain label

A space that places nulls is a different space from one that does not: it
admits a different set of values and gives a meaning to a code the other
leaves unused. The label rule in the ore README, "changing any encoding or
what a code means is a new label", applies, so each policy gets its own
labels:

```
vitaminc/ore/value/<kind>/nulls-first/v1
vitaminc/ore/value/<kind>/nulls-last/v1
```

with `<kind>` as in the existing labels (`int32`, `float64`, `uuid`, and
so on) for the thirteen fixed-width targets, twenty-six new labels in
all. `OrderTarget::domain` gains a policy argument and the `domain`
module gains the new constants and a `domain::ALL` that lists all
forty-one. The salt binds the label as
before, so a term from a nulls-last space never compares with a term from
a plain space of the same target, and turning a policy on for a column is
a re-index, visibly, rather than a mixed column whose stored maximums
silently became nulls.

### 5. Queries for `IS NULL`, `IS NOT NULL` and ranges

`encrypt_query` on a space with a policy accepts a null and gives the
sentinel's query term. A layer answers `IS NULL` with an equality
comparison against it and `IS NOT NULL` with the negation. A range query in
a space with a policy must exclude the sentinel itself, because SQL
comparisons never match a null: `age < 10` under nulls-first is "above the
sentinel and below 10". The space offers the sentinel's query term for
that bound; building the predicate is the layer's work, as it is for every
other predicate, and is noted in the ore README's query section. On a
space without a policy a null query is `NoDomain`, as it is today.

### 6. No scheme capability yet

Nothing in `OrderScheme` changes. The leakage posture is documented, in
the ore README beside `NullOrder` and in this decision, in these words:
in any order index whose stored terms compare with each other, the nulls
are visible as the tied group at one end, and in a sparse domain as the
group that differs from every value at the top of the encoding. When
right-only storage exists (ore.rs#99), a capability on the scheme can
carry the stronger claim, and `nulls` can be gated on it. That is a later
decision.

### 7. Tests and corpus

Known-answer tests pin every sentinel's bytes, every shifted code at the
edges (zero, one, the nil uuid, the value below the maximum) and every
refused maximum, per target and policy, and the plain-space behaviour is
pinned as unchanged. A test walks each encoder's admitted range and
asserts it never produces the sentinel for float, date, timestamp and
decimal. The `test_support` scheme checks gain a nulls-first and a
nulls-last space, so a scheme is checked with an all-zero and an all-ones
fixed plaintext. The shared value corpus is not touched: index
terms are not part of it, and the Go and Node bindings do not produce
terms.

## Consequences

- An index layer gets an equality term for every null it walks, at the
  null's path, under `vitaminc/prf/value/null/v1`. Nothing it stores for a
  present value changes.
- An order space without a policy behaves exactly as before. One with a
  policy gives a null a term, refuses the target's maximum with
  `NormalizeError::Reserved` for integer and uuid targets, and uses a new
  label. Text and bytes take no policy.
- The leakage of a placed null is the tied extreme group, and in sparse
  domains the top-of-encoding tell, under both schemes and in their stored
  terms. It is never more than the SQL `NULL` it replaces. This is stated
  in the docs where the policy is set.
- `ORDER BY ... NULLS FIRST` and `NULLS LAST` on an encrypted column can be
  answered from the index alone, in index order, which is what the stack's
  EQL tests already ask for in SQL and could not get.
- Range predicates on a space with a policy are two-sided. That is a
  change in the layer that builds them, and it is where the policy is
  chosen, so it is one change in one place.
- The Go and Node bindings are unaffected: they carry typed nulls to the
  guest and do not produce index terms.
- The twenty-six new order labels and the one new equality label are
  protocol data from the release that ships them, under the existing rule.
