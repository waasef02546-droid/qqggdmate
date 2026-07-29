# ADR 0006: Make MongoDB a recoverable Provider service backend

- Status: Accepted for a bounded single-active-Provider prototype
- Date: 2026-07-29
- Work package: `CORE-005`
- Claim mapping: new bounded claim `C-008`; refines the service evidence for `C-007`

## Context

CORE-004 verified real Mongo object and rotation-journal conditional updates, but
`MongoProviderRepository` was referenced only by the Mongo experiment. The experiment explicitly
called `save_agent`, `save_data_policy`, `save_data_token`, and related helpers. The HTTP
`ProviderService` still loaded and saved only a JSON aggregate. Consequently, Mongo evidence did
not establish that the actual service could restart, restore an in-progress rotation, or prevent a
stale service instance from overwriting newer state.

## Decision

### Repository contract

`ProviderService` depends on a small `ProviderRepository` contract:

- `load()` returns one validated aggregate with `schema_version` and `state_revision`;
- `save(state, expected_revision=N)` persists revision `N+1` or raises
  `repository_state_conflict`.

JSON and Mongo implement the same contract. JSON retains atomic file replacement and adds a
sequential revision check. Mongo stores the authoritative Provider metadata as one
`provider_state` document and replaces it with a server-side revision compare-and-swap.

### Mongo object boundary

Encrypted objects remain individual documents managed by `MongoEncryptedStore`, with their
existing object-revision CAS. They are deliberately omitted from the embedded Provider aggregate.
On startup, Mongo objects already exist in their collection; the restored rotation journal
validates them through the attached stable store ID and object inventory.

The aggregate document and encrypted-object documents are separate atomicity domains. The
implemented rotation order remains recoverable:

- stage changes the object before advancing aggregate journal evidence;
- commit changes memory before advancing the aggregate terminal state;
- cleanup changes objects before setting the aggregate cleanup marker.

If aggregate persistence fails, the process is fenced. Restart then reloads the previous aggregate
and validates/retries the reachable object state established in CORE-004.

### Fencing

Every service mutation saves with the revision loaded by that process. A stale revision raises
`RepositoryConflict`, marks the process persistence-fenced, and rejects all later service
operations with `repository_recovery_required`. `/healthz` returns HTTP 503 while fenced.

This is stale-writer detection, not leader election. Before the first conflict, two processes may
hold stale reads; the accepted deployment assumption is one active Provider writer.

### Startup and compatibility

- Mongo service construction explicitly selects `--mongo-uri` and `--mongo-db`.
- Startup never calls `reset`.
- A database with legacy physical Provider collections or encrypted objects but no authoritative
  aggregate fails closed and requires explicit migration; it is not silently treated as empty.
- JSON schemas v1-v3 remain readable. JSON and Mongo write schema v3 aggregates with revisions.
- Legacy granular Mongo `save_*` helpers remain temporarily available for compatibility, but the
  authoritative E2E and service do not call them.
- The HTTP server owns and closes its Mongo client.

### Auditable denial

A policy denial reached through authenticated data-token issuance now records and persists a
`data_token_issuance` denial event. This lets the Mongo E2E preserve the intended
contact-allowed/data-denied evidence without bypassing the service to append an audit manually.

## Failure behavior

- Stale aggregate writer: `repository_state_conflict`, then process fencing.
- Operation after fencing: `repository_recovery_required`.
- Mongo/JSON persistence exception after an in-memory mutation: process fencing and restart
  required.
- Legacy/orphan Mongo state without an aggregate: startup fails closed.
- Journal/object mismatch on restart: existing CORE-004 recovery errors remain authoritative.

No failure path exposes private keys, plaintext DEKs, or plaintext records.

## Evidence and limitations

The live Mongo integration drives authenticated HTTP prepare/stage, stops the service, reconstructs
it from the same database, and completes commit/cleanup. A separate two-service test demonstrates
one CAS winner and fencing of the stale process. The migrated Mongo E2E performs registration,
policy setup, Contact issuance, DataToken issuance, PRE consumption, denial, and audit persistence
through `ProviderService`.

This prototype embeds Provider metadata in one Mongo document and is bounded by Mongo's document
size limit. It does not provide multi-document transactions, multi-Provider leader election,
linearizable reads, production authentication, or production PRE/HPKE security.
