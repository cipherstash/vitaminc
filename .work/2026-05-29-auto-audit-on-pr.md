# Auto Audit on PR — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use cipherpowers:executing-plans to implement this plan task-by-task.

**Goal:** Land two GitHub Actions workflows on `main` that auto-review every PR for test-coverage gaps (Tier 1, required check, Claude Sonnet) and every crypto-package PR for crypto vulnerabilities + coverage gaps (Tier 2, advisory, Claude Opus).

**Architecture:** Two workflow files under `.github/workflows/`, both wrapping `anthropics/claude-code-action`. Prompts are markdown files under `.github/audit-prompts/`, version-controlled with the repo. See full design at `.work/auto-audit-on-pr/design.md`.

**Tech Stack:** GitHub Actions YAML, `anthropics/claude-code-action@v1`, Claude Sonnet 4.6 + Claude Opus 4.7, `actionlint` for local YAML validation.

**Ground truth for prompt validation:** the audit artefacts from the manual PR #175 review at `audit/pr-175-{context,findings,coverage-gaps}.md` on the `review-pr-175` worktree (`/Users/auxesis/src/github.com/cipherstash/vitaminc/.claude/worktrees/review-pr-175/audit/`). Expected after rollout: Tier 1 surfaces ≥4 of CG-01..CG-05; Tier 2 surfaces both M-* findings plus ≥2 of the 3 L-* findings.

**Sub-skills referenced:**
- @cipherpowers:test-driven-development for the prompt-validation loop
- @cipherpowers:commit-workflow for each commit step
- @cipherpowers:executing-plans for plan execution

---

## Pre-flight (one-time setup)

### Task 0a: Verify repo-secret access

**Step 1: Check whether `ANTHROPIC_API_KEY` is already set**

Run:
```bash
gh secret list -R cipherstash/vitaminc | grep -i anthropic
```

Expected: either a line `ANTHROPIC_API_KEY ...` (already set — skip to Task 0b) or no output (need to set it).

**Step 2: If not set, set it**

```bash
# Paste the key when prompted. Do NOT paste it into a script file.
gh secret set ANTHROPIC_API_KEY -R cipherstash/vitaminc
```

Expected: `✓ Set Actions secret ANTHROPIC_API_KEY for cipherstash/vitaminc`.

**Step 3: Verify**

```bash
gh secret list -R cipherstash/vitaminc | grep ANTHROPIC_API_KEY
```

Expected: one line showing the secret name and an "Updated <date>" stamp.

**No commit** — secrets are not version-controlled.

### Task 0b: Install `actionlint` locally for YAML validation

**Step 1: Check whether actionlint is already installed**

Run: `which actionlint`

If output shows a path → done, skip to Task 1.

**Step 2: Install actionlint**

```bash
brew install actionlint
```

Expected: brew installs the binary. Final line of output: `==> Pouring actionlint--...` (or similar).

**Step 3: Verify**

```bash
actionlint --version
```

Expected: a version string like `1.7.x`.

**No commit** — local tooling.

---

## Implementation

### Task 1: Create the audit-prompts directory with placeholder files

**Files:**
- Create: `.github/audit-prompts/coverage-review.md` (placeholder)
- Create: `.github/audit-prompts/crypto-audit.md` (placeholder)

**Step 1: Make the directory and add placeholder markers**

```bash
mkdir -p .github/audit-prompts
echo "# placeholder — see Task 4" > .github/audit-prompts/coverage-review.md
echo "# placeholder — see Task 7" > .github/audit-prompts/crypto-audit.md
```

**Step 2: Verify directory layout**

```bash
ls -la .github/audit-prompts/
```

Expected: two files, each ~30 bytes.

**Step 3: Commit**

```bash
git add .github/audit-prompts/
git commit -m "chore(ci): scaffold audit-prompts directory"
```

---

### Task 2: Write the Tier 1 workflow YAML

**Files:**
- Create: `.github/workflows/pr-coverage-review.yml`

**Step 1: Write the workflow**

Create `.github/workflows/pr-coverage-review.yml` with exactly:

```yaml
name: PR Coverage Review

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
    # No paths filter — runs on every PR so the required check is
    # satisfiable on every merge to main.
  workflow_dispatch:
    inputs:
      pr_number:
        description: 'PR number to review (for manual dogfooding)'
        required: true
        type: string

permissions:
  contents: read
  pull-requests: write
  id-token: write

concurrency:
  group: coverage-review-${{ github.event.pull_request.number || github.event.inputs.pr_number }}
  cancel-in-progress: true

jobs:
  coverage-review:
    if: github.event_name == 'workflow_dispatch' || github.event.pull_request.draft == false
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Checkout (PR event)
        if: github.event_name == 'pull_request'
        uses: actions/checkout@v6
        with:
          fetch-depth: 0
      - name: Checkout (manual dispatch — specific PR)
        if: github.event_name == 'workflow_dispatch'
        uses: actions/checkout@v6
        with:
          fetch-depth: 0
          ref: refs/pull/${{ github.event.inputs.pr_number }}/head
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          claude_args: "--model claude-sonnet-4-6"
          prompt: |
            REPO: ${{ github.repository }}
            PR NUMBER: ${{ github.event.pull_request.number || github.event.inputs.pr_number }}

            Your full review instructions are in the file:
            `.github/audit-prompts/coverage-review.md`

            Read that file first using the Read tool, then follow its
            workflow exactly. The PR branch is already checked out in
            the current working directory.

            For inline comments on specific lines, use the
            `mcp__github_inline_comment__create_inline_comment` tool
            with `confirmed: true`. For the top-level review body,
            use `gh pr comment` via Bash.
```

**Why this shape (not `prompt_file` / `model` / `mode` / `allowed_tools`):**
`anthropics/claude-code-action@v1` does not accept those as input keys —
they were v0.x names that v1 removed. The v1 idiom is `prompt` (inline
multi-line string referencing the prompt file by path so Claude reads
it at runtime via the Read tool), `claude_args` for model + CLI flags,
and the action auto-detects the review mode from the event.

**Step 2: Validate YAML with actionlint**

Run:
```bash
actionlint .github/workflows/pr-coverage-review.yml
```

Expected: no output (exit 0). actionlint resolves the upstream
`action.yml` and knows the real v1 input schema; if it reports
"input X is not defined", that's a real error, not a stale-metadata
warning — fix the YAML, do not commit through.

**Step 3: Commit**

```bash
git add .github/workflows/pr-coverage-review.yml
git commit -m "feat(ci): add Tier 1 PR coverage review workflow

Lightweight per-PR coverage review wrapped around
anthropics/claude-code-action. Runs on every PR (incl. doc-only
changes) so the eventual branch-protection required check is
always satisfiable. Includes workflow_dispatch for dogfooding
against arbitrary PR numbers."
```

---

### Task 3: Write the Tier 1 prompt (coverage-review.md)

**Files:**
- Modify: `.github/audit-prompts/coverage-review.md` (overwrite placeholder)

**Step 1: Write the prompt**

Overwrite `.github/audit-prompts/coverage-review.md` with:

```markdown
# Test Coverage Review

You are a test-coverage reviewer for the `vitaminc` Rust cryptography
workspace. Your job is to identify **test coverage gaps for new or
changed code in the current PR**, and post inline review comments
with concrete test sketches the author can adopt.

## Workflow

1. **Read the PR diff first.** Use `git diff origin/$GITHUB_BASE_REF...HEAD`
   or inspect via the GitHub API. Focus on `+` lines only.
2. **For each non-trivial added/changed function or test module**, ask:
   - Is every public method covered by at least one test?
   - Is every branch in the added logic exercised?
   - Are negative cases tested? (wrong-input, wrong-key, malformed)
   - For encode/decode or seal/open pairs: is there a roundtrip test?
   - Are boundary inputs tested? (empty, max-size, exactly-at-limit)
3. **For each gap, post one inline review comment** anchored on the
   relevant line of the PR diff. Each comment must include:
   - One sentence stating the gap.
   - A concrete Rust test sketch (~5-20 lines) the author can drop in.
   - The expected pass/fail behaviour.

## Scope rules

- **In scope:** gaps introduced by *new or changed* code in this PR.
- **Out of scope:** pre-existing untested code that isn't touched by
  the PR. Do not report on those.
- **Out of scope:** crypto vulnerabilities — those are handled by the
  separate `pr-crypto-audit.yml` workflow. If you notice one
  incidentally, mention it briefly in the review summary body, not as
  an inline comment.

## Output rules

- One PR review submitted via the action's review-posting mechanism (top-level body via `gh pr comment`; inline comments via `mcp__github_inline_comment__create_inline_comment` with `confirmed: true`).
- Each inline comment self-contained: gap description + test sketch.
- **Hard cap: 8 inline comments.** If more gaps exist, list the
  overflow items as a bullet list in the review body under
  `## Additional coverage gaps not posted inline`.
- If the diff is doc-only / CI-only / has no test-relevant changes:
  post a one-line review body saying so, post **zero** inline
  comments, exit 0.

## Calibration

- Be conservative: only flag a gap when the missing test is clearly
  worth adding. Tests for trivial getters or one-line wrappers are
  not gaps.
- Prefer test patterns already established in the affected crate
  (look at sibling tests for shape and naming convention).
- If a gap directly mirrors a known anti-pattern (e.g. "AAD mismatch
  is tested but key mismatch is not"), say so — it grounds the
  recommendation.

## Reference categories (from prior manual audits)

- **Untested branches** in new/changed functions.
- **Public API added without tests.**
- **Lopsided negative cases**: e.g. wrong-AAD covered but wrong-key
  missing; one tamper axis tested but the other three are not.
- **Missing roundtrip property tests** for encode/decode pairs.
- **Missing boundary tests**: empty, max-size, exactly-at-limit,
  malformed.
- **Missing nondeterminism assertions** for operations that should
  produce different outputs each call (e.g. fresh-nonce AEAD seal).
```

**Step 2: Verify it's well-formed markdown**

```bash
wc -l .github/audit-prompts/coverage-review.md
```

Expected: ~60–80 lines.

**Step 3: Commit**

```bash
git add .github/audit-prompts/coverage-review.md
git commit -m "feat(ci): add Tier 1 coverage-review prompt"
```

---

### Task 4: Write the Tier 2 workflow YAML

**Files:**
- Create: `.github/workflows/pr-crypto-audit.yml`

**Step 1: Write the workflow**

Create `.github/workflows/pr-crypto-audit.yml` with exactly:

```yaml
name: PR Crypto Audit

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
    paths:
      - 'packages/aead/**'
      - 'packages/encrypt/**'
      - 'packages/protected/**'
      - 'packages/protected-derive/**'
      - 'packages/permutation/**'
      - 'packages/random/**'
      - 'packages/random-derives/**'
      - 'packages/kms/**'
      - 'packages/password/**'
      - 'packages/traits/**'
  workflow_dispatch:
    inputs:
      pr_number:
        description: 'PR number to review (for manual dogfooding)'
        required: true
        type: string

permissions:
  contents: read
  pull-requests: write
  id-token: write

concurrency:
  group: crypto-audit-${{ github.event.pull_request.number || github.event.inputs.pr_number }}
  cancel-in-progress: true

jobs:
  crypto-audit:
    if: github.event_name == 'workflow_dispatch' || github.event.pull_request.draft == false
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - name: Checkout (PR event)
        if: github.event_name == 'pull_request'
        uses: actions/checkout@v6
        with:
          fetch-depth: 0
      - name: Checkout (manual dispatch — specific PR)
        if: github.event_name == 'workflow_dispatch'
        uses: actions/checkout@v6
        with:
          fetch-depth: 0
          ref: refs/pull/${{ github.event.inputs.pr_number }}/head
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          claude_args: "--model claude-opus-4-7"
          prompt: |
            REPO: ${{ github.repository }}
            PR NUMBER: ${{ github.event.pull_request.number || github.event.inputs.pr_number }}

            Your full audit instructions are in the file:
            `.github/audit-prompts/crypto-audit.md`

            Read that file first using the Read tool, then follow its
            three-phase workflow exactly. The PR branch is already
            checked out in the current working directory.

            For inline comments on specific lines, use the
            `mcp__github_inline_comment__create_inline_comment` tool
            with `confirmed: true`. For the top-level review body,
            use `gh pr comment` via Bash.
```

**Why this shape:** same rationale as Task 2 Step 1 — v1 input schema
is `prompt` + `claude_args`, not `prompt_file` / `model` / `mode` /
`allowed_tools`.

**Step 2: Validate YAML with actionlint**

```bash
actionlint .github/workflows/pr-crypto-audit.yml
```

Expected: no output (exit 0). actionlint resolves the upstream
`action.yml` and knows the real v1 input schema; "input X is not
defined" errors are real, not stale-metadata warnings.

**Step 3: Commit**

```bash
git add .github/workflows/pr-crypto-audit.yml
git commit -m "feat(ci): add Tier 2 PR crypto audit workflow

Path-gated to packages/{aead,encrypt,protected,permutation,
random,kms,password,traits}/** and their -derive crates.
Advisory only (does not block merge). Uses Claude Opus and the
crypto-audit.md prompt to perform context-build + vulnerability
hunt + coverage gap analysis in a single PR review."
```

---

### Task 5: Write the Tier 2 prompt (crypto-audit.md)

**Files:**
- Modify: `.github/audit-prompts/crypto-audit.md` (overwrite placeholder)

**Step 1: Write the prompt**

Overwrite `.github/audit-prompts/crypto-audit.md` with:

```markdown
# Crypto Audit + Coverage Review

You are auditing a Rust cryptography library PR for **both security
vulnerabilities and test coverage gaps**. Output a single PR review
covering both, with inline comments tagged by finding category.

## Workflow — three internal phases, one review output

### Phase 1: Internal context-build (NO output yet)

For each non-trivial new/changed function in the diff, internally
note:
- Inputs (parameters, AAD shape, plaintext/ciphertext shape).
- Outputs (return type, error shape, side effects).
- Trust assumptions (caller-controlled vs cipher-controlled state).
- Cross-references (calls into existing primitives, callers of this).

Do not post anything from this phase. Use it to ground Phases 2 and 3.

### Phase 2: Vulnerability hunt

Categories to detect (PR-#175 patterns plus standard AEAD audit
checklist):

- **Panic-on-untrusted-input.** Unchecked array indexing, slicing,
  `unwrap`/`expect` on Result types fed from caller bytes. Look in
  particular at any `read_nonce`-style prefix extraction or any
  `try_into::<[u8; N]>()` on attacker-controlled length.
- **Missing AAD or key binding.** Any seal/open path that doesn't
  bind both. Any AAD that's accepted but silently dropped.
- **Broken zeroize chain.** `Protected<T>` losing its guard (e.g.
  `risky_unwrap` outside the cipher boundary, or a struct that
  declares `ZeroizeOnDrop` but has no `Drop` impl).
- **Doc/code mismatch on security properties.** Doc comments
  claiming guarantees the implementation doesn't currently provide
  (e.g. "this zeroizes on drop" when no Drop is implemented).
- **Type-level invariants defeated by `pub` fields.** A newtype
  whose `pub`-field allows external construction from arbitrary
  bytes, bypassing the producer-side invariant.
- **Byte-shape ambiguity allowing confusion attacks.** Two
  semantically distinct ciphertext types whose serialized bytes are
  identical, allowing on-the-wire substitution.
- **`unsafe` blocks**, `transmute`, `mem::forget`, raw pointer use.
- **Timing channels.** Secret-dependent branches, secret-indexed
  table lookups, secret-length-dependent loops.

**Severity scale:** Critical / High / Medium / Low. **Do NOT post
Info-level findings as inline comments** — informational items go
into the review summary body under `## Informational notes` if at
all, or are skipped entirely if borderline.

**Calibration:** catch real defects with concrete remediation
suggestions. Do not produce audit-memo style "design observations".

### Phase 3: Coverage gap analysis

Categories beyond Tier 1's general set (crypto-specific):

- **Missing panic-on-malformed-input tests.** If Phase 2 found
  panic-on-untrusted-input or you found a potential one, a test
  asserting the API returns `Err` (or panics, marked
  `#[should_panic]`) on under-length / over-length / structurally
  malformed inputs.
- **Missing confusion-attack tests.** For each byte-shape ambiguity
  noted in Phase 2, a test that constructs the ambiguous case and
  asserts the API rejects it.
- **Missing wrong-key tests.** Negative tests that vary the key
  (separate cipher instance) and assert decrypt/verify fails.
- **Missing four-axis tamper tests.** GCM-like AEAD has four axes:
  nonce, ciphertext body, tag, AAD. If only one or two are tested
  negatively, flag the missing ones.
- **Missing nondeterminism / fresh-nonce assertions.** For
  operations that should produce different outputs each call (any
  fresh-nonce AEAD seal), a test that calls twice with the same
  inputs and asserts the outputs differ.

## Output rules

- One PR review submitted via the action's review-posting mechanism (top-level body via `gh pr comment`; inline comments via `mcp__github_inline_comment__create_inline_comment` with `confirmed: true`).
- Inline comments tagged: `[Finding M-XX]`, `[Finding L-XX]`,
  `[Finding H-XX]`, `[Finding C-XX]` (Crit), `[Coverage CG-XX]`.
- **Hard cap: 10 inline comments.** Overflow goes into the review
  summary body under `## Additional items not posted inline`.
- The review summary body has two top-level sections:
  - `## Findings` — bulleted list of all severities posted inline,
    with one-line summaries and severity tags.
  - `## Coverage gaps` — bulleted list of all coverage items posted
    inline.
- If no findings and no coverage gaps: post a one-line review body
  saying so, post **zero** inline comments, exit 0.

## Calibration

- Severity calibration:
  - **Critical**: exploitable with no preconditions; key recovery,
    plaintext recovery without key, signature forgery, etc.
  - **High**: exploitable with limited preconditions; e.g. panic
    reachable from a real downstream usage pattern.
  - **Medium**: exploitable with notable preconditions or with
    bounded impact (e.g. DoS, recovery via specific same-process
    construction).
  - **Low**: defensive/hygiene issues that are not directly
    exploitable but matter for layered defence.
- Be conservative: prefer fewer high-confidence findings over many
  uncertain ones. The fix recommendation should be concrete and
  single-file when possible.

## Reference categories (from PR #175 manual audit ground truth)

Examples to calibrate against — these are the kinds of findings
that should be surfaced:
- M-01-pattern: panic-on-under-length in `read_nonce` via public
  newtype with `From<Vec<u8>>` constructor.
- M-02-pattern: doc claims `Protected<T>` zeroizes on drop, but
  no `Drop` impl exists.
- L-01-pattern: `pub` newtype field bypasses producer invariant.
- L-02-pattern: byte-identical `Encrypted{empty}` and `Absent`
  under same AAD; type-level distinction only.
- L-03-pattern: empty cargo feature added with no gated code.

These should be detectable by your Phase 2 scan if equivalents
exist in this PR's diff.
```

**Step 2: Verify length**

```bash
wc -l .github/audit-prompts/crypto-audit.md
```

Expected: ~150–250 lines.

**Step 3: Commit**

```bash
git add .github/audit-prompts/crypto-audit.md
git commit -m "feat(ci): add Tier 2 crypto-audit prompt

Three-phase prompt (context-build → vuln hunt → coverage gaps)
producing a single PR review with inline comments tagged by
finding ID. Calibrated against PR #175 ground truth: M-01, M-02,
L-01, L-02, L-03 patterns are explicitly enumerated as reference
categories the prompt should be able to surface."
```

---

### Task 6: Run actionlint over the entire `.github/workflows/` dir

**Step 1: Lint everything**

```bash
actionlint .github/workflows/
```

Expected: no output (exit 0). If pre-existing workflows have warnings, that's not blocking — focus on the two new files.

**Step 2: Spot-check with `gh workflow list` (after push)**

Skip this step until Task 8 — `gh workflow list` shows workflows present on the remote branch; we haven't pushed yet.

**No commit** — verification only.

---

### Task 7: Push the branch and open a draft PR

**Step 1: Confirm clean working tree on the right branch**

```bash
git -C /Users/auxesis/src/github.com/cipherstash/vitaminc/.claude/worktrees/auto-audit-design status
git -C /Users/auxesis/src/github.com/cipherstash/vitaminc/.claude/worktrees/auto-audit-design log --oneline main..HEAD
```

Expected:
- `status`: `On branch feat/auto-pr-review`, `working tree clean`.
- `log`: 5 commits (the design.md commit from earlier + the 4 implementation commits).

**Step 2: Push the branch**

```bash
git -C /Users/auxesis/src/github.com/cipherstash/vitaminc/.claude/worktrees/auto-audit-design push -u origin feat/auto-pr-review
```

Expected: `branch 'feat/auto-pr-review' set up to track 'origin/feat/auto-pr-review'`.

**Step 3: Open the draft PR**

```bash
gh pr create --base main --head feat/auto-pr-review --draft \
  --title "feat(ci): automated PR audit workflow" \
  --body "$(cat <<'EOF'
## Summary

Two-tier automated PR review on every PR to vitaminc:

- **Tier 1 — `pr-coverage-review.yml`**: lightweight test-coverage
  review on every PR via Claude Sonnet. Eventually a required check
  on `main`.
- **Tier 2 — `pr-crypto-audit.yml`**: deep crypto + coverage audit
  on PRs touching `packages/{aead,encrypt,protected,permutation,
  random,kms,password,traits}/**` via Claude Opus. Advisory only.

Both wrap `anthropics/claude-code-action@v1`. Prompts live as
markdown under `.github/audit-prompts/` so they version-control
with the rest of the repo.

## Design

Full design at `.work/auto-audit-on-pr/design.md` on this branch.

## Test plan

- [x] `actionlint .github/workflows/pr-coverage-review.yml` — clean
- [x] `actionlint .github/workflows/pr-crypto-audit.yml` — clean
- [ ] Tier 1 fires on this PR itself (touches `.github/` only — no
      crypto paths, so Tier 2 should NOT fire). Watch the run and
      review comments.
- [ ] Once this PR is merged, manually dogfood both workflows
      against a recent PR (e.g. #175) via `workflow_dispatch`. See
      the rollout runbook in `.work/2026-05-29-auto-audit-on-pr.md`.
- [ ] After dogfood looks correct, flip Tier 1 to required check on
      `main` branch protection.

## Rollout

This PR ships both workflows as **advisory**. Required-check
promotion happens in a follow-up PR (or via repo settings) after
dogfooding.
EOF
)"
```

Expected: a URL like `https://github.com/cipherstash/vitaminc/pull/XXX`. Record the PR number — call it `$NEW_PR`.

**No commit** — PR creation only.

---

### Task 8: Smoke-test — wait for Tier 1 to fire on the bootstrap PR

The PR itself touches `.github/workflows/` and `.github/audit-prompts/` and `.work/`. No `packages/**` path. So Tier 1 should fire; Tier 2 should NOT.

**Step 1: List workflow runs for the branch**

```bash
gh run list --branch feat/auto-pr-review --workflow pr-coverage-review.yml --limit 5
```

Expected: at least one run with status `in_progress` or `completed`. If `completed`, conclusion should be `success`.

**Step 2: Confirm Tier 2 did NOT fire**

```bash
gh run list --branch feat/auto-pr-review --workflow pr-crypto-audit.yml --limit 5
```

Expected: no runs (path filter correctly excluded this PR).

**Step 3: Read the Tier 1 review on the PR**

```bash
gh pr view "$NEW_PR" --json reviews,comments | jq '.reviews[] | {state, body: (.body | .[0:200])}'
```

Expected: at least one review from the `github-actions` bot (or whatever account the action posts as). State `COMMENTED`. Body should mention "doc-only / CI-only" or similar — because the PR has no Rust code changes, the prompt's calibration rule says post zero inline comments.

If the review body looks like a generic Claude reply rather than a calibrated coverage review, the prompt needs tuning — proceed to Task 9.

**No commit** — verification.

---

### Task 9: Tune the Tier 1 prompt if needed

**Step 1: Compare the review output against expected behaviour**

Expected behaviour from the prompt's "Output rules":
- One PR review submitted via the action's review-posting mechanism (top-level body via `gh pr comment`; inline comments via `mcp__github_inline_comment__create_inline_comment` with `confirmed: true`).
- For a CI/doc-only PR: one-line body, zero inline comments.

If the actual output diverges (e.g. Claude found "gaps" in YAML files, posted >0 inline comments, or wrote a long review body when it shouldn't), the prompt needs tightening.

**Step 2: Edit `.github/audit-prompts/coverage-review.md`**

Likely tweaks based on observed divergences:
- Strengthen "Out of scope" rules (CI YAML, docs).
- Reinforce the "post zero comments on no-code-change PRs" instruction.
- Add an explicit example of an acceptable empty-review output at the bottom of the file.

**Step 3: Commit the tweak**

```bash
git add .github/audit-prompts/coverage-review.md
git commit -m "fix(ci): tighten coverage-review prompt for doc-only PRs"
git push
```

**Step 4: Trigger a fresh run by force-pushing or re-running**

Either push a trivial commit to retrigger, or:
```bash
gh run rerun $(gh run list --branch feat/auto-pr-review --workflow pr-coverage-review.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```

**Step 5: Re-verify per Task 8 Step 3.**

Iterate Step 2–5 up to 2 times. If the prompt still misbehaves after 2 iterations, escalate to a manual prompt review session — the loop is too tight in CI.

---

### Task 10: Dogfood Tier 1 against PR #175 via workflow_dispatch

**Step 1: Trigger Tier 1 against PR #175**

```bash
gh workflow run pr-coverage-review.yml \
  --ref feat/auto-pr-review \
  -f pr_number=175
```

Expected: `✓ Created workflow_dispatch event for pr-coverage-review.yml at feat/auto-pr-review`.

**Step 2: Wait for run completion**

```bash
gh run watch $(gh run list --workflow pr-coverage-review.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```

Expected: run finishes with conclusion `success`. ~3-5 minutes.

**Step 3: Check the new review on PR #175**

```bash
gh pr view 175 --json reviews | jq '.reviews[-1] | {state, submittedAt, body}'
```

Expected: a new review submitted within the last 10 minutes.

**Step 4: Compare against ground truth**

The ground truth coverage gaps are at
`/Users/auxesis/src/github.com/cipherstash/vitaminc/.claude/worktrees/review-pr-175/audit/pr-175-coverage-gaps.md`,
specifically CG-01 through CG-05 (Important tier).

Read the new Tier 1 review and check:
- Does it mention panic-on-under-length tests (CG-01)? Probably yes
  on PR #175 because that PR has the panic-prone `read_nonce` call.
- Does it mention wrong-key tests (CG-03)? Should — the PR only
  tests wrong-AAD.
- Does it mention four-axis tamper tests (CG-04)? Should.
- Does it mention nondeterminism / fresh-nonce assertions (CG-05)?
  Should.

**Pass condition: ≥4 of CG-01..CG-05 are surfaced (any form).**

**Step 5: If pass — done with Tier 1 validation. If not — tune prompt and re-run.**

Iterate Step 2 of Task 9 against the gap, push, re-dispatch. Cap at
3 iterations before escalating.

**No commit** — dogfood + verification only.

---

### Task 11: Dogfood Tier 2 against PR #175 via workflow_dispatch

**Step 1: Trigger Tier 2 against PR #175**

```bash
gh workflow run pr-crypto-audit.yml \
  --ref feat/auto-pr-review \
  -f pr_number=175
```

**Step 2: Wait for run completion**

```bash
gh run watch $(gh run list --workflow pr-crypto-audit.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```

Expected: ~10-20 min (Opus + larger prompt).

**Step 3: Check the new review on PR #175**

```bash
gh pr view 175 --json reviews | jq '.reviews[-1] | {state, submittedAt, body}'
```

Expected: a new review with both findings and coverage gap sections.

**Step 4: Compare against ground truth**

The ground truth findings are at
`/Users/auxesis/src/github.com/cipherstash/vitaminc/.claude/worktrees/review-pr-175/audit/pr-175-findings.md`.

Pass condition (per design Phase B exit criteria):
- ≥2/2 of M-* findings surfaced (M-01 panic-on-under-length,
  M-02 doc/code mismatch on Protected zeroize).
- ≥2/3 of L-* findings surfaced (any of L-01 pub-field, L-02
  byte-shape ambiguity, L-03 empty cargo feature).
- ≥4/5 of CG-01..CG-05 surfaced.

**Step 5: If pass — done with Tier 2 validation. If not — tune
prompt and re-run.**

Iteration loop is the same as Task 9 Step 2, but applied to
`.github/audit-prompts/crypto-audit.md`. Cap at 3 iterations.

**Step 6: Commit any prompt tunings + push**

Per-iteration:
```bash
git add .github/audit-prompts/crypto-audit.md
git commit -m "fix(ci): tighten crypto-audit prompt — <specific reason>"
git push
```

---

### Task 12: Mark draft PR ready for review

**Step 1: Verify all dogfood checks passed**

Cross-reference: `[ ]` items in the PR description's test plan should
now be `[x]`. Edit the PR description if needed:

```bash
gh pr edit "$NEW_PR" --body "<updated body with checked boxes>"
```

**Step 2: Mark ready**

```bash
gh pr ready "$NEW_PR"
```

Expected: `✓ Pull request <#XXX> is marked as ready for review`.

**Step 3: Request review**

```bash
gh pr edit "$NEW_PR" --add-reviewer coderdan
```

(Or whoever the appropriate reviewer is.)

**No commit** — PR state change only.

---

## Post-merge runbook (operational, not engineering)

Once the PR merges to `main`, the next phases are operational. They
are **not** engineering tasks — they are watch + tweak loops.

### Phase A → B: Watch advisory output on 2-3 real PRs

For the first 2-3 PRs after merge:

1. Read the Tier 1 review.
2. If Tier 2 fires, read it too.
3. Note any false positives (findings the author dismisses) — track
   in a follow-up issue if patterns emerge.
4. Note any false negatives (real issues a human reviewer caught
   that Claude missed) — also track.

If the ratio is acceptable (>4 useful findings per false positive),
proceed to Phase B.

### Phase B: Flip Tier 1 to required check

After ~2 weeks of advisory operation:

**Step 1: Update branch protection**

```bash
gh api repos/cipherstash/vitaminc/branches/main/protection \
  --method PUT --input -<<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["coverage-review", "Test"]
  },
  ...
}
EOF
```

(Use `gh api repos/cipherstash/vitaminc/branches/main/protection` to
read the current settings, edit JSON, and PUT back. Easiest path:
do this via the repo UI: Settings → Branches → Edit `main` rule →
add `coverage-review` to required status checks.)

**Step 2: Open a PR to test the gate**

Open a trivial PR, confirm the required check appears, confirm
merge is blocked until the check passes.

### Phase C: Quarterly prompt review

Once per quarter:

1. Read all reviews posted by the workflows in the past quarter.
2. Identify recurring false-positive or false-negative patterns.
3. Tune the prompt files accordingly.
4. Commit prompt updates via a normal PR.

---

## Verification — end-to-end checklist

When this plan is complete, the following should hold:

- [ ] `.github/workflows/pr-coverage-review.yml` exists on `main`.
- [ ] `.github/workflows/pr-crypto-audit.yml` exists on `main`.
- [ ] `.github/audit-prompts/coverage-review.md` exists on `main`.
- [ ] `.github/audit-prompts/crypto-audit.md` exists on `main`.
- [ ] `ANTHROPIC_API_KEY` repo secret is set.
- [ ] Tier 1 workflow ran on at least one real PR after merge and
      posted a review.
- [ ] Tier 2 workflow ran on at least one crypto-package-touching
      PR after merge and posted a review with both findings and
      coverage gap sections.
- [ ] The Tier 1 dogfood run against PR #175 surfaced ≥4 of
      CG-01..CG-05.
- [ ] The Tier 2 dogfood run against PR #175 surfaced both M-*
      findings + ≥2 L-* findings + ≥4 of CG-01..CG-05.

Phase B promotion (Tier 1 → required check) is **out of scope** for
this implementation plan — it's an operational change handled in
the runbook after engineering work is complete.
