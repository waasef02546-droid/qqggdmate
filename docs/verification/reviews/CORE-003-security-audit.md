# CORE-003 independent security audit

- Date: 2026-07-28
- Scope: owner-wrapped DEK provenance and owner-key rotation lifecycle
- Method: read-only implementation, test, ledger, ADR, claim, experiment, and paper review
- Implementation verification: bounded pass; persistence-recovery and real Mongo gates remain open

## Pre-implementation findings

| Severity | Finding | Required disposition |
|---|---|---|
| P0 | In-memory and Mongo stores accept a caller-supplied owner public key and persist no registration provenance. | Resolve an active `AgentRecord` inside the authoritative write path and persist owner AID, fingerprint, registration version, registration ID, and key algorithm. Remove the raw-key write API. |
| P0 | Re-encryption accepts caller-supplied owner-wrapped DEK and opaque rekey bytes without resolving an authoritative stored object. | Resolve by record ID, validate stored provenance before token consumption, and remove raw-EDEK override from the data plane. |
| P1 | Immediate registration replacement has no prepare/rewrap/commit or abort lifecycle. | Implement the ADR 0004 staged, non-destructive state machine with actor and expected-version checks. |
| P1 | Store writes, rotation, and consumption have no shared concurrency boundary. | Add owner-scoped process locking, conditional persistence, observable conflicts, and fail-closed race behavior. |
| P1 | Legacy and malformed Mongo encrypted objects are silently deserialized. | Quarantine or reject incomplete provenance and require explicit authenticated migration. |
| P2 | The existing stale-rekey experiment changes a data-record version, not an owner registration or owner wrap. | Keep it as data-version evidence and add a distinct owner-rotation attack artifact. |
| P2 | Current claims and formal artifacts cover requester registration or static transform authorization, not owner-wrap provenance and rotation. | Add a separately bounded claim only after implementation evidence; state the formal exclusion unless a new model is verified. |

## Required invariant

A transformed owner-wrapped DEK must come from the authoritative stored object named by the request,
and that object must carry a complete provenance tuple matching its record and the owner
registration selected by the explicit rotation lifecycle. Provenance denial occurs before
`DataToken.remaining_uses` changes and before the PRE backend is invoked.

ADR 0004 defines the agreed schema, `prepare -> staging -> staged -> commit` lifecycle, abort and
recovery behavior, raw-key/EDEK removal, and bounded persistence guarantees.

## Acceptance matrix

| Class | Minimum falsifying checks | Pending evidence |
|---|---|---|
| Positive | Active owner registration produces all provenance fields; normal old-key transform succeeds; staged rotation retains old usability; complete commit selects the new wrap; new owner decrypts. | New store-provenance unit tests and owner-rotation integration tests. |
| Negative | Raw owner key/EDEK override, unknown/revoked/legacy owner, missing/malformed/tampered provenance, record-owner mismatch, stale old wrap/rekey after commit, wrong actor/version, and incomplete commit all fail before PRE/token consumption. | Direct store, App/HTTP, and attack-path checks. |
| Boundary | Zero/one/many objects, unsupported algorithm, duplicate/idempotent operations, writes or deletes during rotation, abort before/after partial staging, and repeated commit/abort. | Rotation state-machine unit tests. |
| Concurrency | Competing prepare/commit, write versus prepare/commit, consumption versus commit, and backend/persistence failure produce a complete old/new state or denial, never mixed authorization. | Barrier-driven in-process tests; conditional Mongo conflict tests. |
| Persistence | Valid provenance and each lifecycle state round-trip; legacy/corrupt state quarantines; prepared/failed rotations resume or abort after restart; committed state restores consistently. | JSON restart integration and a real Mongo lifecycle run. |

## Existing evidence that may be reused

- CORE-002 focused evidence may support unchanged registration fingerprinting, management actor and
  expected-version checks, requester binding, and management/data-plane separation.
- Existing envelope unit tests may support unchanged AEAD serialization, tamper rejection, and
  cross-context failure.
- CORE-001/CORE-002 Contact, policy, token signature, and one-use results remain predecessor
  evidence only where their implementation and fixtures are unchanged.
- Repository layout hygiene evidence is unaffected by this core mechanism.

None of those results verifies owner registration provenance, staged owner-key rotation, recovery,
or Mongo lifecycle behavior. The prior full regression skipped Mongo and cannot be relabeled as a
CORE-003 pass.

## Claim and paper boundary

- Do not broaden `C-003`: owner-side unwrap/rewrap handles plaintext DEK in the trusted owner/store
  boundary. The Provider/PRE proxy non-observation claim can remain only if rewrap does not execute
  there.
- Do not broaden requester-path `C-006`. Add a separate proposed `C-007` for authoritative
  owner-wrap provenance and the single-process staged lifecycle after focused evidence passes.
- State that Mongo distributed atomicity and crash-safe multi-process rotation are not established.
- State that toy PRE/HPKE test doubles do not prove rekey-target authenticity, secure erasure, or
  production cryptographic security.
- Existing ProVerif artifacts do not model rotation state, persistence recovery, or concurrency.
- Paper references to stale rekey/data version must not be cited as owner identity-key rotation
  evidence.

## Verification and closure status

Post-implementation review confirms that raw owner-key writes and raw-EDEK data-plane overrides
were removed, provenance-bound dual wraps and staged activation were implemented, and validation
precedes token consumption. Focused verification passed 35 affected tests after integration, and
the final isolated regression passed 79 tests with one Mongo skip.

Before acceptance:

1. implement the authoritative write and consumption paths plus the ADR 0004 lifecycle;
2. pass the focused acceptance matrix and record exact commands/environment in the ledger;
3. produce a representative owner-rotation attack artifact if an experimental claim is made;
4. run a real targeted Mongo lifecycle check, or mark Mongo behavior blocked and narrow the
   accepted criterion and claim;
5. update the claims matrix, milestone, and any directly affected protocol/paper wording; and
6. run one isolated full regression only if the final schema/API impact remains cross-cutting,
   then run the repository control checker after evidence-document updates.

The single-process in-memory claim is prototype-bounded. Rotation restart recovery, staged-wrap
cleanup, multi-process linearizability, and real Mongo lifecycle behavior remain unsupported and
must not be inferred from this package.
