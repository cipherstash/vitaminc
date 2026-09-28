# Design — Automated PR Audit Workflow

Two-tier automated review on every PR to `vitaminc`, derived from the
manual audit pattern applied to PR #175.

## Context

PR #175 was reviewed manually using a multi-step pipeline:
audit-context-building (pure context, no findings) → vulnerability hunt
→ test coverage gap analysis → inline review comments posted via the
GitHub API. The artefacts are at `audit/pr-175-*.md` on the
`review-pr-175` worktree.

That review took ~15 minutes of orchestrated subagent work, produced
2 medium + 3 low security findings (all five posted inline) and
15 coverage gaps (top 5 posted inline). It cost on the order of a few
dollars in Claude API spend. Reproducing this quality manually on
every PR is impractical — both for cost-of-attention and consistency.

The goal of this design: bake that review pattern into CI as
`anthropics/claude-code-action` workflows so every PR gets at least
some review for crypto vulnerabilities and test coverage gaps, with
deeper coverage automatically targeted at the highest-stakes paths.

## Architecture

Two new workflow files plus a prompt directory:

```
.github/
├── workflows/
│   ├── test.yml                  (existing — Rust tests)
│   ├── release-plz.yml           (existing — release automation)
│   ├── pr-coverage-review.yml    (NEW — lightweight, required check)
│   └── pr-crypto-audit.yml       (NEW — deep, advisory)
└── audit-prompts/                (NEW — version-controlled prompts)
    ├── coverage-review.md
    └── crypto-audit.md
```

**Tier 1 — Lightweight coverage review** (`pr-coverage-review.yml`):

- Triggers on every PR open/synchronize/reopen/ready_for_review.
- Single Claude Sonnet invocation via `anthropics/claude-code-action`.
- Scans the diff for **test coverage gaps in new or changed code only**.
- Posts inline review comments on lines where coverage is missing.
- **Required status check** on `main` branch protection. The check
  passes when the action exits 0 (Claude posted its review — *not*
  "Claude found zero issues"); it fails only on auth/API errors or
  crashed runs. The required check enforces *that a review happened*,
  not *that there are no findings*.

**Tier 2 — Deep crypto audit** (`pr-crypto-audit.yml`):

- Triggers only when paths matching crypto-sensitive packages change.
- Single Claude Opus invocation.
- Performs the manual workflow's three-phase shape:
  context-building → vulnerability hunt → coverage gap analysis.
- Posts a single PR review with two grouped sections of inline comments
  (findings + coverage).
- **Advisory only** — never blocks merge.

A PR that touches crypto paths gets both reviews (Tier 2 fires
*in addition to* Tier 1). The coverage findings will overlap slightly;
acceptable for the simplicity of independent triggers.

## Tier 1 — Lightweight coverage review

```yaml
# .github/workflows/pr-coverage-review.yml
name: PR Coverage Review

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
    # No paths filter — runs on every PR, including doc/CI-only changes,
    # so the required check is satisfiable on every merge to main.

permissions:
  contents: read
  pull-requests: write

concurrency:
  group: coverage-review-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  coverage-review:
    if: github.event.pull_request.draft == false
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0   # full history so Claude can see context beyond the diff
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          model: claude-sonnet-4-6
          prompt_file: .github/audit-prompts/coverage-review.md
          mode: review              # posts a single PR review with inline comments
          allowed_tools: "Read,Grep,Glob,Bash"
```

**Prompt outline** (`.github/audit-prompts/coverage-review.md`, ~80 lines):

1. Role: test-coverage reviewer for the vitaminc crypto workspace.
2. Inputs available: the PR diff, the full source tree at PR head.
3. Scope: gaps for *new or changed* code only. Skip pre-existing
   untested code unless directly related to the diff.
4. Gap categories to detect:
   - Untested branches in new/changed functions.
   - Public API methods added with no tests.
   - Negative cases tested with one shape only (e.g. wrong-key missing
     when wrong-aad is tested).
   - Missing roundtrip property tests for encode/decode pairs.
   - Untested input boundary conditions (empty, max-size, malformed).
5. Output rules:
   - One single PR review (`mode: review`).
   - Each inline comment self-contained, with a concrete test sketch.
   - Cap inline comments at 8. Extra items go into the review body.
   - If the diff is doc-only or has nothing meaningful to test: post
     a single-line review body saying so, post no inline comments,
     exit 0.

**Required-check wiring:**

Branch protection on `main` adds `coverage-review` as a required
status check. Path-only PRs (CI YAML, docs) still run the workflow —
Claude sees the diff, says "no findings", review is posted with an
empty inline-comment list, exit 0. The check passes. No fork-PR
carve-out needed because we use `pull_request` trigger (no secrets
exposed in untrusted contexts).

## Tier 2 — Deep crypto audit

```yaml
# .github/workflows/pr-crypto-audit.yml
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

permissions:
  contents: read
  pull-requests: write

concurrency:
  group: crypto-audit-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  crypto-audit:
    if: github.event.pull_request.draft == false
    runs-on: ubuntu-latest
    timeout-minutes: 30          # Opus + multi-step pipeline can be slow
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          model: claude-opus-4-7
          prompt_file: .github/audit-prompts/crypto-audit.md
          mode: review
          allowed_tools: "Read,Grep,Glob,Bash"
```

**Prompt outline** (`.github/audit-prompts/crypto-audit.md`, ~250 lines):

1. Role: auditor of a Rust cryptography library PR. Output covers
   both security vulnerabilities AND test coverage gaps.
2. **Phase 1 — internal context build (no output).** Read the diff.
   For each non-trivial new/changed function: inputs, outputs,
   assumptions, cross-references. Don't post anything from this phase.
3. **Phase 2 — vulnerability hunt.** Categories:
   - Panic-on-untrusted-input (unchecked array indexing, slicing,
     `unwrap` on Result types fed from external bytes).
   - Missing AAD / key binding.
   - Broken zeroize chain (Protected without Drop, risky_unwrap
     escaping a guard boundary).
   - Doc/code mismatch on security properties (the M-02 pattern).
   - Type-level invariants defeated by `pub` fields (the L-01 pattern).
   - Byte-shape ambiguity allowing confusion attacks (the L-02 pattern).
   - `unsafe` blocks, `transmute`, `mem::forget`, raw pointers.
   - Timing channels (secret-dependent branches / indexing).

   Severity: **Critical / High / Medium / Low** only. **Do NOT post
   Info-level findings as inline comments** — informational items go
   into the review summary body as a brief "notes" list, or are
   skipped entirely if borderline. Calibration target: catch real
   defects with concrete remediation, not produce audit-memo style
   "design observations".
4. **Phase 3 — coverage gap analysis.** Same categories as Tier 1,
   plus crypto-specific ones:
   - Missing panic tests for under-length / malformed inputs (CG-01).
   - Missing confusion-attack tests for type-tag-vs-byte-shape
     mismatches (CG-02).
   - Missing wrong-key tests (CG-03).
   - Missing tamper tests across all four axes of AEAD authentication
     — nonce, ciphertext, tag, AAD (CG-04).
   - Missing nondeterminism / nonce-uniqueness assertions (CG-05).
5. Output rules:
   - One PR review (`mode: review`) with two grouped sections in the
     body: "Findings" and "Coverage gaps".
   - Inline comments tagged with finding IDs (`[Finding M-01]`,
     `[Coverage CG-01]`) so each comment is self-identifying.
   - Cap inline comments at 10. Items below the cap stay inline; the
     rest get bundled into the summary body.
   - If no findings or coverage gaps: post a single review body
     stating that explicitly, post no inline comments, exit 0.

## Operations

**Secrets.** Single repo secret `ANTHROPIC_API_KEY`:

```bash
gh secret set ANTHROPIC_API_KEY -R cipherstash/vitaminc
```

Scoped to Actions only (default).

**Fork PR handling.** Both workflows use `pull_request`, not
`pull_request_target`. Fork-PRs run *without* secrets in the runner,
so the `claude-code-action` step exits silently. Practical
consequence: external contributor PRs don't get auto-reviewed until
a maintainer pushes a commit to the branch. Trade-off chosen: safer
secrets-handling > immediate fork-PR coverage. Reasonable for an
internal-first crypto library.

**Draft PRs.** Both workflows have
`if: github.event.pull_request.draft == false` and listen for the
`ready_for_review` event. Draft PRs accumulate zero compute cost;
conversion to ready fires the review.

**Cost estimate** (rough, in 2026 USD):

- Tier 1 (Sonnet, ~50k input + ~10k output per PR): **~$0.20–0.50 per PR**.
  At 200 PRs/year ≈ **$40–100/year**.
- Tier 2 (Opus, ~200k input + ~30k output per PR): **~$3–6 per PR**.
  At 50 crypto-touching PRs/year ≈ **$150–300/year**.
- Total: under **$500/year** typical, capped well under **$2000/year**
  even at 4× expected volume.

**Failure modes and mitigations:**

- *Claude API outage* → workflow fails → required check fails →
  merge blocked. Mitigation: admins can override branch protection
  in genuine emergencies, or temporarily mark the check non-required
  via repo settings.
- *Cost spike* (someone opens 100 PRs in a day) →
  `concurrency.cancel-in-progress` prevents stale runs; per-PR cost
  is bounded. Add `paths-ignore: ['CHANGELOG.md']` to suppress
  release-plz churn if it becomes a problem.
- *Prompt drift* → prompts live in `.github/audit-prompts/`,
  version-controlled, reviewed via normal PR workflow. Changes to
  prompts go through the same review they enforce.

## Rollout plan

1. **Phase A — both tiers as advisory.** Land both workflows. Tier 1
   is *not yet* the required check. Watch output on 2-3 real PRs.
   Tune prompts based on false-positive / false-negative patterns.
2. **Phase B — dogfood against ground truth.** Manually trigger both
   workflows (via `workflow_dispatch`) against PR #175 — the
   ground-truth case we already audited manually. Compare against
   `audit/pr-175-findings.md` and `audit/pr-175-coverage-gaps.md`.
   Expected: Tier 1 catches CG-01..CG-05 directly; Tier 2 catches at
   least M-01 + M-02 + 2 of the 3 Lows. Tune prompts to match
   ground truth ±1 item.
3. **Phase C — flip Tier 1 to required check.** Update `main`
   branch protection to add `coverage-review` as a required check.
   Watch 5-10 real PRs for false-positive merge-block incidents.
4. **Phase D — quarterly prompt review.** Schedule a recurring
   30-minute review of the prompts each quarter, with the audit
   docs (`audit/pr-*-{findings,coverage-gaps}.md` accumulating over
   time) as input. Prompts evolve as the codebase evolves.

## Success criteria

Exit Phase B when:

- Both workflows run to completion against PR #175 without manual
  intervention.
- Tier 2 catches ≥80% of M-* findings from the manual audit doc.
- Tier 1 catches ≥80% of CG-01..CG-05 from the manual audit doc.
- False-positive rate (findings the maintainer dismisses as
  incorrect) ≤20% on the 2-3 real PRs from Phase A.

Exit Phase C when:

- Zero false-positive merge blocks in the first 10 real PRs after
  flipping the required check.
- Author triage time per review averages < 5 minutes.

## Out of scope

The following deliberately stay out of this design — they belong to
later iterations:

- **Custom skills as repo deps.** The manual workflow used the
  `audit-context-building` plugin skill. The CI prompts inline its
  pattern rather than depending on plugin marketplace versions. Keeps
  CI reproducible; means prompt maintainers carry the pattern in their
  heads or in the prompt itself.
- **Multi-step orchestration.** `claude-code-action` is a single
  Claude invocation. The manual workflow's three-phase shape becomes
  three *internal* phases inside one invocation, not three jobs. If
  this proves too unwieldy for the Opus prompt, a future iteration
  can switch to a custom shell pipeline.
- **External LLM review (`second-opinion` skill).** Not wired into
  CI — kept as a manual-only escalation for contentious PRs.
- **Fork PR coverage.** Requires `pull_request_target` and careful
  diff-only handling. Out of scope for the internal-first phase.
- **Cost dashboarding.** GitHub Actions usage tab + per-workflow
  billing visibility is enough for now. A dedicated dashboard can
  come if costs exceed projection.
