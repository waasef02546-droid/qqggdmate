# CORE-004 security and acceptance audit

- Date: 2026-07-29
- Scope: persistent rotation journal, restart recovery, terminal wrap cleanup, and live MongoDB CAS
- Verdict: accepted as a bounded single-provider prototype after focused and full verification

## Implemented security properties

1. Rotation entries no longer contain process-local store objects. Stable store IDs and prepared
   object revisions form a serializable recovery inventory.
2. Commit and abort retain terminal history. A restart can distinguish pending, committed, aborted,
   partially cleaned, and fully cleaned states.
3. JSON schema v3 persists registrations, encrypted objects, and the journal in one atomic file
   replacement. Restore validates the registry state, object set, object revisions, and exact
   source/target wrap counts before accepting the journal.
4. Cleanup remains behind the trusted management capability and is bound to the original actor,
   AID, and rotation ID.
5. Abort removes only the target wrap tagged by the exact rotation. Commit removes only the
   matching source registration wrap and retains the exact target.
6. In-memory and Mongo cleanup are idempotent. Mongo stage/cleanup and journal transitions use
   server-side conditional filters; stale conditions do not overwrite newer state.
7. No journal or persisted object contains plaintext data, a plaintext DEK, or a private key.

## Verification results

- Final focused run: 19 tests passed across restart recovery, abort/commit cleanup, idempotency,
  corrupt journal rejection, prior rotation behavior, Provider HTTP persistence, management/data
  separation, provenance, and live Mongo CAS.
- MongoDB 8.3.4 process restart probe: the prepared-to-committed conditional update matched once,
  the stale prepared condition matched zero times, and the committed record remained after the
  server stopped and restarted on the same isolated data directory.
- Final isolated regression: 83 tests ran; 82 passed and the legacy Mongo E2E test skipped because
  it is fixed to port 27017. The new live-Mongo rotation test used the isolated port 27018 and
  passed in that same regression.
- The first full regression exposed a real integration defect: all policy-aware stores inherited
  the same default stable store ID. Assigning one deterministic ID per data class resolved it; the
  complete suite then passed.
- Serena diagnostics found and corrected an optional store-ID type boundary. Its Pyright process
  later reported contradictory duplicate-module types and stale `TrustedManagementPlane` members;
  these environment diagnostics are not counted as clean static-analysis evidence. Runtime
  compilation and the complete test suite are the acceptance evidence.

## Residual risks and non-claims

- JSON atomic replacement is a single-process persistence boundary, not a database transaction.
- MongoDB updates are atomic per document. Registration activation, journal transition, and
  multiple object updates are not one distributed transaction.
- Partial multi-object cleanup is observable and recoverable by retry, but not instantaneously
  atomic.
- Stable store IDs are configuration identity. Rebinding an existing ID to a different store is
  rejected; operators must preserve IDs across restart.
- Static Bearer management authentication, toy PRE/HPKE, lack of HSM/KMS, and lack of a
  multi-process lease remain prototype limitations.
- Formal ProVerif artifacts do not yet model this persistent recovery state machine.

## Claim decision

`C-007` may be strengthened only to a restart-recoverable single-provider lifecycle with
per-document Mongo compare-and-swap evidence. It must not claim crash-safe distributed rotation,
multi-process linearizability, production PRE security, or transactionally atomic multi-object
cleanup.
