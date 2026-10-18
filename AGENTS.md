# Agent guidelines for vitaminc

The project guidelines for agents are in `CLAUDE.md`. This file holds the
guidance for agents that review pull requests.

## Review guidelines

### Known non-findings

These are deliberate design decisions. Do not report them as defects or
security issues, and do not change the code to "fix" them. If a change
seems to need one reversed, say so and link the ADR, rather than flagging
the property itself.

- **A sealed container's membership, order and length are not
  authenticated.** Each leaf is bound to its context, its map key, its role
  (single value or sequence element), its type tag and the wire version. But
  which entries a map holds, and a sequence's order, length and duplicates,
  are deliberately not bound: vitaminc's values are stored as database rows
  and columns, which come back in any order and in part. A map with an entry
  missing, or a sequence reordered or truncated, still opens leaf by leaf; a
  decrypt target that then refuses its shape reports a shape mismatch, not a
  failed authentication. Stricter authentication will be opt-in, through
  named types. See `docs/adr/0002-leaves-are-authenticated-container-membership-and-order-are-not.md`.
  A leaf that is *not* bound to its context, key, role, type or version is
  still a real defect: report that.
