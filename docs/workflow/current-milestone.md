# Current milestone

## Active work package

- ID: `CORE-004`
- Title: Persistent rotation journal, restart recovery, and terminal wrap cleanup
- State: `accepted_prototype_bounded`
- Authorization date: `2026-07-29`
- Acceptance date: `2026-07-29`
- Objective: persist the owner-key rotation state machine and encrypted-object lifecycle across
  provider restart, recover incomplete work without trusting stale state, clean staged/source
  wraps idempotently after abort/commit, and verify MongoDB conditional updates on a real service.
- Authorized scope: serializable rotation journal entries and terminal history; JSON state schema
  migration; encrypted-object snapshot/restore; recovery validation; management-plane cleanup
  operations; in-memory and Mongo per-object conditional cleanup; focused restart, corruption,
  idempotency, conflict, and live-Mongo verification; ADR, claims, and reproducibility evidence.
- Primary core modules:
  - `project/presaga/storage/encrypted_store.py`
  - `project/presaga/storage/mongo_encrypted_store.py`
  - `project/presaga/provider/registry.py`
  - `project/presaga/provider/app.py`
  - `project/presaga/provider/server.py`
  - `project/presaga/provider/json_repository.py`
- Non-goals: production cryptography; HSM/KMS; cross-document or distributed atomicity; changing
  PRE-SAGA policy semantics, experiment conclusions, or paper claims beyond matching implemented
  evidence; moving held user/runtime/tool directories; or adding an unauthenticated cleanup path.

## Selected orchestration mode

- Mode: `A`
- Rule: the primary agent owns architecture, core integration, and the evidence chain. Read-only
  MCP review may run before edits. Subagents are used only if two or more genuinely independent
  audits remain after semantic inspection, with one writer per overlapping component.

## Acceptance criteria

- Prepared, committed, and aborted rotations have immutable identifiers and persist as terminal
  audit history instead of disappearing from memory.
- A restart restores registrations, encrypted objects, and pending rotation inventory, rejects
  malformed/inconsistent journals, and permits safe resume, abort, or cleanup.
- Abort cleanup conditionally removes only wraps staged by that rotation. Commit cleanup
  conditionally retires the matching source wrap while preserving the active target wrap.
  Both operations are idempotent and fail closed on object-revision conflicts.
- The JSON repository migrates explicitly to the new state schema. The Mongo-backed store uses
  server-side conditional updates and preserves the same cleanup invariants.
- Live MongoDB evidence demonstrates successful conditional update, stale-revision rejection, and
  persistence after reconnect/restart against an isolated database.
- Focused positive, negative, boundary, restart, and concurrency checks pass. A full regression
  runs because the provider persistence schema and owner-store protocol are cross-cutting.
- Claims and limitations remain bounded to a recoverable single-provider research prototype with
  per-document CAS, not a distributed atomic rotation or production cryptographic system.

## Evidence obligations

- Use Serena read-only semantic queries to trace the existing prepared-rotation and store
  persistence boundaries before choosing the design.
- Record the journal schema, recovery validation, cleanup transitions, failure modes, JSON
  migration, and Mongo atomicity boundary in an ADR before acceptance.
- Check the test ledger before each run and preserve unrelated dirty/untracked user material.
- Update the claims matrix, test ledger, and this milestone after implementation and verification.

## Completed prerequisite: repository layout migration

- The old prototype, legacy config and result CSV, Stage-2 evidence, and SAGA comparison reviews
  were moved to their documented authoritative/archive locations with before/after integrity
  checks.
- `project/` remains the only authoritative engineering tree; no compatibility links or duplicate
  implementation copies were created.
- `Record/`, `results/compare/`, `runtime/`, `tools/`, `tmp/`, `saga_reproduction/`, and private
  reference inputs were deliberately not moved.
- Recovery instructions and hashes are recorded in
  `docs/repository/layout-migration-2026-07-28.md` and
  `docs/repository/archive-manifest.yaml`.
- Repository hygiene and the 24-file control-plane check pass. Functional tests were not rerun
  because the migration changed no current implementation or active configuration.

## Risks

- Per-document Mongo CAS does not make a multi-object rotation atomic; implemented partial cleanup
  remains observable and resumable.
- JSON persistence assumes one Provider writer and stable logical store IDs across restart.
- Persisting encrypted-object metadata increases the corruption surface; implemented restore
  validation rejects unreachable journal/object combinations before serving data.
- The legacy Mongo E2E still hardcodes port 27017; CORE-004 live evidence comes from its dedicated
  environment-configurable test and process restart probe on port 27018.
- Toy backends permit owner-side unwrap/rewrap but do not establish production PRE security.

## Verification evidence

- Final focused integration passed 19 tests covering JSON restart/resume, corrupt recovery,
  commit/abort cleanup, idempotency, prior owner-rotation behavior, Provider HTTP persistence,
  management/data-plane separation, provenance, and live Mongo CAS.
- A MongoDB 8.3.4 process-level probe on isolated port 27018 recorded conditional match 1, stale
  match 0, then preserved the committed state after stopping and restarting the server with the
  same data directory.
- The first isolated full regression found a real stable-store-ID collision among policy-aware
  stores. Deterministic per-data-class IDs corrected the integration defect.
- Final isolated full regression ran 83 tests: 82 passed; one legacy Mongo E2E skipped because it
  is fixed to port 27017. The new CORE-004 live-Mongo test passed on port 27018.
- JSON schema v3, terminal history, recovery invariants, cleanup transitions, conditional Mongo
  boundaries, evidence, and non-claims are recorded in ADR 0005 and the CORE-004 security audit.
- Repository workflow control, Python compilation, YAML parsing, and whitespace validation pass.

## Previous accepted work packages

- `CORE-003`: accepted on `2026-07-28`; registration-bound owner-wrap provenance, explicit
  prepare/rewrap/commit lifecycle, and per-object Mongo CAS established.
- `CORE-002`: accepted on `2026-07-28`; authenticated AID-to-key binding, versioned registry,
  management/data-plane separation, persistence migration, and MCP review tooling established.
- `CFG-002`: accepted on `2026-07-28`; repository normalization, readable guidance, canonical
  engineering tree, recoverable archive plan, and Git baseline established.
- `CORE-001`: accepted on `2026-07-26`; server-enforced Contact-to-data-token-to-re-encryption
  binding implemented and verified.

## Proposed next work package

- Candidate: not selected; a paper/experiment claim gap review should choose it.
- State: `awaiting_user_choice`
- Rule: do not begin another package automatically.
