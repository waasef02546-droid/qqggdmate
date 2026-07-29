# CORE-005 security and acceptance audit

- Date: 2026-07-29
- Scope: Mongo-backed recoverable Provider service
- Verdict: accepted as a bounded single-active-Provider prototype

## Authoritative path review

- Serena symbol references confirmed that `MongoProviderRepository` was previously instantiated
  only by `project/experiments/e2e/mongodb_e2e.py`; `ProviderService` accepted only
  `JsonProviderRepository`.
- `ProviderService` now consumes the repository protocol, owns the loaded aggregate revision, and
  automatically persists service mutations.
- Mongo service creation wires `MongoProviderRepository` and `MongoEncryptedStore` to the same
  database without reset. The server closes its Mongo client.
- The Mongo E2E contains no granular `repo.save_*` calls; normal and denial evidence uses service
  methods.

## Security properties verified

1. Mongo HTTP rotation survives a stop after stage and restores the exact pending journal/object
   state before commit and cleanup.
2. Two Provider instances loaded at revision zero cannot both persist revision one. The loser is
   fenced, cannot answer later audit/service calls, and cannot overwrite the winning registration.
3. Legacy/orphan Mongo object state without an authoritative aggregate fails startup.
4. JSON uses the same aggregate revision contract and rejects a sequential stale writer.
5. Contact-compatible Mallory receives a persisted data-token issuance denial through the same
   service path used by the experiment.
6. The final isolated regression passed all 87 discovered tests with live MongoDB enabled; no
   Mongo test was skipped.

## Residual risks and non-claims

- The accepted topology has one active Provider writer. CAS detects conflicting writes but is not
  leader election and does not make stale reads linearizable.
- Provider aggregate metadata and encrypted objects are separate atomicity domains. Recovery is
  fail-closed and retryable, not transactionally instantaneous.
- The aggregate document has a bounded research-prototype scale and no compaction/history policy.
- Legacy granular Mongo collections require explicit migration and are rejected by the new
  service when no aggregate exists.
- Static Bearer management authentication and toy PRE/HPKE remain non-production.
- The ProVerif models do not model repository revisions, process fencing, or Mongo failure modes.

## Claim decision

The evidence supports `C-008`: a bounded single-active Provider can use MongoDB as an automatic,
restart-recoverable service backend and fences a stale writer after aggregate CAS failure. It does
not support distributed atomicity, multi-Provider availability, or production cryptographic
security.
