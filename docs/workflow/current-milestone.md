# Current milestone

## Active work package

- ID: `REL-001`
- Title: Authoritative experiment provenance and paper-grade release gate
- State: `accepted`
- Authorization date: `2026-07-29`
- Objective: make the published PRE-SAGA experiment tables, figures, formal outputs, SAGA bridge,
  and Mongo E2E traceable to one current source state and one authoritative Provider decision path,
  then verify them with a tamper-evident release manifest.
- Authorized scope:
  - move data-token issuance audit ownership into the authoritative Provider domain path;
  - remove experiment-only policy decisions and duplicate policy evaluation from PRE-SAGA flows;
  - add a staged release runner and independent manifest verifier;
  - execute fresh attack, task, performance, formal, bridge, and live-Mongo evidence;
  - synchronize traceability, claims, paper results, limitations, and reproducibility guidance.
- Primary implementation paths:
  - `project/presaga/provider/app.py`
  - `project/presaga/provider/server.py`
  - `project/experiments/`
  - `project/scripts/`
  - `project/results/`
  - `project/docs/traceability_matrix.md`
  - `paper/`
- Non-goals: production PRE/HPKE; RAFT, sharding, or multi-Provider linearizability; real cloud/on-
  device LLM or geolocation experiments; full SAGA OTK/DH/ACT runtime integration; or claiming
  parity with every evaluation dimension of arXiv:2504.21034v2.

## Selected orchestration mode

- Mode: primary-agent implementation with three bounded read-only audits.
- Rule: subagents inspect experiment provenance, paper-claim consistency, and clean-environment
  reproducibility independently. The primary agent owns architecture, all writes, integration,
  test selection, and final claim decisions.

## Acceptance criteria

- Every allowed or denied call to the Provider domain's data-token issuance path records one
  `data_token_issuance` audit event and returns its audit identifier.
- The HTTP service persists that domain audit without creating a duplicate event.
- Published PRE-SAGA attacks obtain policy denial from `PREProviderApp.request_data_token` or
  token consumption from `PREProviderApp.request_re_encryption`; they do not synthesize a
  publication result by invoking `DataPolicyEvaluator` and manually appending an audit.
- Full-flow performance and scalability measurements do not evaluate the same data policy once in
  the experiment and again inside the Provider.
- One release command writes into staging, enforces attack/task/proof/bridge/Mongo gates, publishes
  only a passing artifact set, and writes source/config/artifact hashes in a release manifest.
- An independent verifier accepts the fresh manifest and rejects missing, modified, or failed-gate
  evidence.
- Focused positive, denial, persistence, artifact-tamper, and boundary tests pass. One full
  regression is justified because Provider audit behavior and the combined experiment entry point
  are cross-cutting.
- Claims and paper wording remain explicitly prototype-bounded and distinguish this local evidence
  from SAGA's real LLM, geographic, RAFT, and sharding evaluation.

## Evidence obligations

- Record the pre-change provenance gaps and the final decision in ADR 0007.
- Preserve every failed test or release run in the ledger and link the causal correction.
- Run the release with real ProVerif 2.05 and isolated MongoDB 8.3.4 when locally available.
- Record exact artifact hashes, source-tree fingerprint, environment, gate results, and verifier
  outcome.
- Update claims `C-002` and `C-004` only to the level justified by the fresh manifest.
- Keep performance results descriptive; timing variation is not a security proof.

## Risks

- The worktree contains user and prior-work-package edits, so a source fingerprint is stronger than
  an ambiguous branch name but remains uncommitted until a deliberate Git baseline is created.
- Timing outputs vary across machines and runs. Correctness gates and artifact schema are
  deterministic; latency values are not.
- ProVerif models cover bounded token/DEK/rekey properties and do not model persistent rotation,
  repository fencing, Mongo failure, or the full implementation.
- The SAGA bridge consumes recorded SAGA reproduction evidence and is not direct runtime
  interoperability.
- Mongo evidence is a single-host local run and does not establish distributed transactions,
  failover, RAFT, or sharding.
- Toy PRE/HPKE and static management authentication remain non-production.

## Verification evidence

- Data-token issuance auditing is owned by the Provider domain and returns one
  audit identifier for allow and policy-deny decisions.
- Publication-facing attacks, tasks, full-service performance/scalability, and
  the SAGA bridge cross `ProviderService`; modeled microbenchmarks are labeled.
- Accepted release: `20260729T123951Z-23c9fbf1`.
- Clean release-input commit:
  `6109b3eb6318a9714ee29b65da2340be5a6abcdf`.
- Accepted evidence commit:
  `b91e501`.
- Source fingerprint:
  `fc8c5a40159d622cca1830dc0f25582d2f76a32a4e146e7f19fbefc80e8af195`.
- Release gates: 7/7 blocking attacks, 1/1 active ToyPRE limitation probe, 4/4
  tasks, 12/12 performance rows, 3/3 ProVerif models with four verified
  queries, 2/2 SAGA bridge cases, and live Mongo E2E.
- Release-input cleanliness gate: pass; unrelated workspace materials remain
  outside the release input set and are recorded separately.
- Independent release verifier: pass.
- Focused verification: 22/22.
- Full regression with MongoDB 8.3.4: 89/89, no skips.
- Acceptance review:
  `docs/verification/reviews/REL-001-release-acceptance.md`.
- Claim correction: ToyPRE public-material DEK recovery is reproduced;
  concrete Provider confidentiality remains unsupported.

## Previous accepted work packages

- `CORE-005`: accepted on `2026-07-29`; revisioned JSON/Mongo repository contract, restart recovery,
  service-driven Mongo E2E, and stale-writer fencing established.
- `FE-001`: accepted on `2026-07-29`; local PRE-SAGA demonstration console and loopback Provider
  proxy established without changing scientific claims.
- `CORE-004`: accepted on `2026-07-29`; persistent rotation history, JSON restart recovery,
  terminal cleanup, and live Mongo per-document CAS established.
- `CORE-003`: accepted on `2026-07-28`; registration-bound owner-wrap provenance and authenticated
  prepare/rewrap/commit or abort lifecycle established.
- `CORE-002`: accepted on `2026-07-28`; authenticated AID-to-key binding, versioned registry, and
  management/data-plane separation established.
- `CFG-002`: accepted on `2026-07-28`; repository normalization and canonical engineering layout
  established.
- `CORE-001`: accepted on `2026-07-26`; server-enforced Contact-to-data-token-to-re-encryption
  binding established.

## Proposed next work package

- Candidate ID: `CRYPTO-001`
- Candidate topic: replace ToyPRE with a reviewed concrete backend and define a
  malicious-Provider recovery gate that the real backend must block.
- State: `awaiting_user_choice`
- Rule: do not begin this candidate automatically.
