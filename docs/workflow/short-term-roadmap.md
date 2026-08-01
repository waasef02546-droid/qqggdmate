# PRE-SAGA short-term roadmap

## Baseline and operating decision

- Baseline branch: `codex/keycustody-001`.
- Accepted mechanism: `KEYCUSTODY-001`, source commit
  `5f1cea694249397095672867d087daab4630be36`, authoritative release
  `20260731T111704Z-c1d0f804`.
- Closure status: accepted implementation and evidence; the post-push control-plane check is
  recorded separately and does not change the release fingerprint.
- Execution mode: workflow A. Authorize and close one core work package at a time. The primary
  agent owns architecture, integration, staging, and final acceptance.
- Near-term allocation target: at least two core mechanism packages before the evidence-only
  evaluation package. Tests are selected from changed behavior and never count as the core output.

## Ordered work packages

### 1. KFRAGSCOPE-001 — per-record-version delegating-key separation

- Priority: immediate; scientific impact very high; implementation risk high.
- Intended effort split: approximately 70% core implementation and 30% verification/evidence.
- Objective: prevent a requester retaining record A's KFrag from recovering record B's DEK by
  applying that KFrag directly to B's Umbral capsule, even when PRE-SAGA Provider/context checks
  are bypassed.
- Smallest coherent mechanism: owner/KMS-held deterministic derivation of a distinct Umbral
  delegating key for each canonical record-version label; an owner-authority-signed public key
  binding; persisted wrapper provenance; Provider verification against authoritative record state.
- Claim boundary: authenticated per-record-version key separation over
  `nucypher-core==0.15.0`, not native label-bound PRE. Same-record-version KFrag copying,
  post-decryption exfiltration, KMS compromise, HSM properties, and legacy ciphertext erasure stay
  outside the claim.
- Start gate: explicit user authorization of `KFRAGSCOPE-001` after review of the draft checklist.

### 2. REQUESTPOP-001 — requester proof-of-possession and replay control

- Priority: second; depends on stable key roles and provenance from `KFRAGSCOPE-001`.
- Intended effort split: approximately 65% core implementation and 35% verification/evidence.
- Objective: replace field-only requester identity on contact, token, and re-encryption data-plane
  requests with a canonical signed proof bound to the action, subjects, resource identifiers, body
  digest, nonce, and expiry.
- Required production path: verification against the active authoritative registration plus a
  JSON/Mongo-persistent replay journal with restart and CAS semantics.
- Required design decision: reuse the Umbral key with an explicit prototype limitation, or register
  a distinct signing key. Decide this at package authorization; do not mix it into KFRAGSCOPE.
- Non-goals: mTLS, OIDC, administrative identity, and remote attestation.

### 3. EVALROBUST-001 — process-separated statistical evaluation

- Priority: third; begins only after the crypto and request schemas stabilize.
- Intended effort split: approximately 45% experiment implementation and 55% evidence analysis.
- Objective: evaluate the authoritative HTTP path with versioned workloads, raw per-trial data,
  failure counts, setup/steady-state separation, median/P95, and confidence intervals.
- Comparisons: JSON versus live Mongo and matched local ablations using the same serialization,
  storage, and workload. These are not presented as a fair external SAGA baseline.
- Deliverables: reproducible configurations/seeds, raw data, generated tables/figures, provenance
  checks in the release verifier, and an updated threats-to-validity section.

## Work that intentionally waits

- Live SAGA interoperability and a fair external baseline, because they require external access
  and stable protocol APIs.
- Second-host clean-checkout reproduction and independent `nucypher-core` adapter review, which
  should target the stabilized release candidate.
- Broad formal modeling of rotation journals, Mongo CAS, and fencing unless a future package makes
  a formal claim about them.
- HSM certification, mTLS, remote attestation, secure erasure, distributed transactions, frontend
  integration, and final venue/template polishing.

## Orchestration and review loop

1. Primary agent writes the bounded package contract and freezes the file ownership map.
2. Up to three subagents work only on genuinely independent areas: threat/design audit,
   non-overlapping implementation, and evidence/acceptance review.
3. One writer owns every overlapping Provider, storage, or cryptography file. Subagents return
   conclusions, file references, risks, and proposed actions rather than raw logs.
4. Integrate the smallest production path first; add focused positive, negative, and boundary
   checks for the behavior changed.
5. Compare each test request with `docs/verification/test-ledger.yaml`. A full suite is run only
   when cross-cutting schemas/interfaces or the release gate justify it.
6. Run an independent acceptance audit against the checklist. Fix unmet items and repeat only the
   affected checks until all gates are evidenced.
7. Update claims, limitations, traceability, ledger, milestone, and release provenance together.
8. Stop after acceptance. Propose the following package, but do not begin it without authorization.

## Repository and Git boundary

- Authoritative engineering code and evidence remain under `project/`; the authoritative paper is
  `paper/pre_saga_paper.md`, and authoritative release evidence is under `project/results/`.
- Existing modified `paper/pre_saga_draft.md` and `paper/publication_plan.md`, and existing untracked
  frontend/history/draft/result material, are user-owned boundaries. Do not clean, move, delete, or
  stage them as part of these packages.
- Every package uses an explicit staging allowlist. Destructive cleanup, legacy migration, remote
  publication, or force push requires its own exact authorization.
