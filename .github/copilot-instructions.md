# Copilot instructions for vitaminc

## Code review

A sealed container's membership, order and length are not authenticated,
by design: a map's set of entries, and a sequence's order, length and
duplicates, are not bound into any AAD, because sealed values are stored as
database rows and columns that come back in any order and in part. Do not
report this as a defect. A leaf that is not bound to its context, map key,
role (single value or sequence element), type tag or wire version is still a
defect.

Emptiness is the exception, and is authenticated: an empty sequence or map
is sealed as an authenticated marker (`EmptySequence`, `EmptyMap`), and a
reader refuses a sequence or map that holds no sealed leaf. A change that
weakens either check is a defect. See
`docs/adr/0002-leaves-are-authenticated-container-membership-and-order-are-not.md`
and the "Review guidelines" in `AGENTS.md`.
