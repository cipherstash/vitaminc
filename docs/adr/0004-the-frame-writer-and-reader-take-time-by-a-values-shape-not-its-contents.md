---
status: proposed
---

# The frame writer and reader take time by a value's shape, not its contents

> **Proposed.** Follows the writer and reader work in
> [#559](https://github.com/cipherstash/vitaminc/pull/559) and
> [#560](https://github.com/cipherstash/vitaminc/pull/560), and records
> what a timing probe of that code found on 2026-10-29. The numbers are
> from that probe; the decision is what to promise, what to fix and what
> to say no to.

A value is serialized before it is sealed and after it is opened, so the
serde writer and reader in `vitaminc-aead-frame` run over plaintext. The
time they take is visible to anyone who can time the operation around
them: a request's latency, or a neighbour on the same machine. This
decision says how much of the plaintext that time may reveal. It promises
the shape and nothing else, and names the three places the code reveals
more today.

## Context

The format writes a value's shape into its bytes: every length, every
count, every kind byte, and whether an `Option` holds something. The time
to write or read a value follows its shape too, since a longer text is
copied longer. That is inherent to a variable-length format, and the same
is true of the ciphertext's length. Hiding the shape means padding to a
fixed one, which is a sealing-layer decision, not a format one.

Within one shape, the question is whether two values take the same time.
A probe in the style of dudect (Reparaz, Balasch and Verbauwhede, 2017)
was run against the writer and reader at the tip of #560. Two classes of
input share a shape and differ only in their values: one is a single value
made from a fixed seed, the other a fresh random value per sample, both
built by the same code so that both classes allocate alike. Samples are
interleaved at random, each timing a batch of runs of one operation.
Welch's t statistic is taken on the raw timings and on the fastest 90, 70,
50, 30 and 10 percent of each class, and the largest |t| is reported, with
4.5 as the threshold. Each workload runs a random-against-random control
pair as well, and every control stayed below 4.0. Two seeds, 20,000
samples per pair (5,000 for the map, text and bytes workloads), Apple M4,
rustc 1.98.1, fat LTO. Reads were timed into the target type and into
`serde::de::IgnoredAny`, which walks and validates the bytes and builds
nothing, so the target type's own allocation and parsing stay out of the
reader's timing.

Clean on both seeds, in both profiles, write and read: integers of every
width, floats, ASCII text including its UTF-8 validation, `Some`, bytes,
and a map of random text keys read through either profile. Three things
were not clean, on both seeds, with the control quiet:

| What | Where | Cost | Largest t |
| --- | --- | --- | --- |
| A bool's value | `leaf::write_physical` picks `BOOL_TRUE` or `BOOL_FALSE` with a branch; the reader branches on the tag the same way | about 0.2 ns per bool written, 1 ns per bool validated: a random bool mispredicts, a steady one does not | 44 to 83 on write, 504 to 630 on a validating read |
| How much neighbouring map keys share | `storage::distinct` sorts key identities and compares neighbours with an early-exit compare, in the storage writer and the storage validator; the transport writer's sort of key byte ranges does the same | about 1.3 ns per compare: 64 keys sharing a two-byte prefix cost 80 ns more than 64 random keys | 211 to 287 in the storage writer, 121 to 146 in the storage validator, 10 to 14 in the transport writer |
| A `Display` value's magnitude | `collect_str` formats the value in place with `core::fmt`, whose integer formatting does work per digit before it pads | a `u64` of one shown as twenty padded digits writes in 80 ns where a random one takes 39 | 1,974 to 5,060 |

A `Display` value's reader is clean: the harness's own parse of the text
back to a number leaked, and that is the type's `Deserialize`, not the
format's.

Two things the probe did not cover: multibyte UTF-8 against ASCII of the
same byte length, which takes the validator's slower path, and x86.

## Decision

1. **The promise is the shape.** The time to write or read a value with
   either profile depends on the value's shape: its types, the length of
   each text and bytes value, the count of each container, which `Option`
   holds something, and the nesting. It does not depend on the values
   themselves. STORAGE.md and the crate documentation say this, and say
   that the shape is also in the bytes, so a reader of the bytes learns
   no less than a timer does.

2. **A bool is written and read without a branch on its value.**
   `BOOL_FALSE` is `0x02` and `BOOL_TRUE` is `0x03`, so the writer's tag
   is `BOOL_FALSE | u8::from(value)` and the reader's value is
   `tag == BOOL_TRUE` under one arm for both tags. The bytes do not
   change. The storage corpus and the conformance vectors pin that.

3. **A repeated key is found without comparing key bytes to each other.**
   Both profiles' writers and validators find a repeated key the way the
   transport validator does today: a hash set keyed with random bytes,
   over the key's identity, so an integer key of any width hashes to the
   same entry and a text or bytes key hashes its bytes. The time is then
   the sum of hashing each key, which depends on each key's length, not
   on how keys compare. A map's keys are no longer sorted at all.

   This replaces `storage::distinct` and the transport writer's sort of
   key ranges. The transport map write will get slower, since its sort was
   cheaper than a hash set for a thousand keys; the storage map write may
   get faster, since `distinct` reads each key's node to sort it. Both are
   measured when it is done, and the probe is run again.

4. **A `Display` value leaks what its formatting leaks, and the
   documentation says so.** The writer cannot format a number in constant
   time on the type's behalf. `collect_str` is documented as taking the
   time its `Display` takes, and a type that holds a secret number is told
   to serialize the number, not its text. The same note covers the
   reader: a type that parses text back is on its own.

5. **The probe is kept and run before the writer or reader changes
   ship.** It lives in the crate as a bench that is not run by `cargo
   bench` by default, with the same workloads, seeds, sample counts and
   threshold as above, and a control pair per workload. A change to the
   writer, the reader, the leaf codec or the validators runs it on both
   seeds, and the result goes in the pull request. A row over the
   threshold on both seeds is a finding to fix or to add to this record.
   It is not a CI gate: a t statistic on a shared runner is noise.

6. **What is not promised.** Nothing about the shape; nothing about the
   allocator, which is the caller's; nothing about the sealing layer,
   whose cipher has its own promise; nothing about a `Serialize` or
   `Deserialize` impl's own work. The promise is for the code in this
   crate and in `vitaminc-aead`'s leaf codec between the value and the
   bytes.

## Consequences

- The three findings become two fixes and one note. The bool fix is a
  few lines in two places and costs nothing. The key fix is a design
  change to `distinct` and the transport writer's map end, measured
  against the tables in the README when it lands.
- The leak that is closed is small in absolute terms: nanoseconds per
  bool or per key compare, which a remote attacker cannot see and a local
  one needs many thousands of samples to see. The reason to close it is
  the promise, not the exploit: with it, a reader of the code knows what
  the timing depends on without measuring, and the probe keeps it so.
- A map's keys stop being sorted, so the writer no longer learns their
  order. Nothing depended on that: the bytes keep the order the
  `Serialize` gave, as STORAGE.md says.
- The shape stays visible in time as in bytes. A caller who needs to hide
  it pads the value before sealing it, and this record is the place that
  says that is the caller's job.
- The probe adds a bench file and about three hundred lines to the crate,
  and a line to the pull request template for changes that touch the
  writer or reader.

## Alternatives considered

- **Constant-time compares inside the sort.** A fixed-width compare of
  the integer identities is branchless, but a sort's number of compares
  still follows the input's order, and text keys are of varying length,
  so the sort stays data-dependent. A sorting network over variable-length
  keys is a lot of code for a map that a hash set handles.
- **Comparing every pair of keys in constant time.** Data-oblivious, but
  quadratic: a thousand keys is half a million compares, around a hundred
  times the whole write today.
- **Keeping the sort and documenting the leak.** What a timer learns is
  how much neighbouring keys share, which for a map of field names or
  identifiers is little. But it is a leak of key contents, the hash set
  closes it at a cost measured in microseconds on a thousand keys, and a
  promise with an exception for maps is harder to state than one without.
- **Formatting `Display` values in constant time.** Would mean a numeric
  formatter of the crate's own, used only when a type chooses text over
  numbers. The type can choose numbers.
- **Padding to a fixed shape in the format.** Would hide the shape from
  the bytes and from time, but the shape to pad to is the caller's
  knowledge, not the format's, and the sealing layer already owns the
  ciphertext's length.
- **A CI gate on the probe.** Welch's t on a shared runner moves with the
  runner's load, and a gate that fails on noise is turned off. A pull
  request that reports the probe's result from a quiet machine is the
  gate.
