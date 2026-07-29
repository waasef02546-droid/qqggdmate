# ADR 0005: Persist rotation recovery state and clean terminal wraps conditionally

- Status: Accepted for the bounded single-provider prototype
- Date: 2026-07-29
- Work package: `CORE-004`
- Claim mapping: refines `C-007`

## Context

CORE-003 made owner-key replacement explicit, but its prepared entry contained live Python store
references and was deleted on commit or abort. Provider JSON state did not include encrypted
objects or rotation state. A restart therefore lost both the recovery plan and the evidence needed
to decide whether an object was unstaged, staged, or already cleaned. Staged target wraps also
remained after abort, while source wraps remained after commit.

## Decision

### Durable journal

Each rotation has an immutable `rotation_id` and a serializable journal entry containing:

- source registration ID and version;
- complete candidate registration;
- authenticated management principal;
- stable store ID and the prepared object-ID/revision inventory;
- `prepared`, `committed`, or `aborted` status;
- creation/update timestamps; and
- an idempotent `cleanup_completed` marker.

Commit and abort retain terminal journal history. Only `prepared` entries occupy the one-pending-
rotation-per-AID slot.

### JSON recovery boundary

Provider state schema v3 atomically writes registrations, encrypted-object snapshots, and the
rotation journal in the same JSON replacement. Restore order is registrations, encrypted objects,
then journal entries. Older schema-v1/v2 state remains readable and receives empty v3 collections;
newer unknown schemas fail closed.

Recovery validates registration fingerprints and versions, stable store IDs, unique inventories,
the exact owner object set, reachable revision values, and source/target wrap counts. A journal
that cannot describe the persisted object state is rejected before the service is available.

### Terminal cleanup

Cleanup is an authenticated management-plane action.

- After abort, each object either remains at its prepared revision with only the source wrap, or
  conditionally removes the target wrap carrying that exact `rotation_id`.
- After commit, each object must contain the exact target wrap; cleanup conditionally retires the
  source registration wrap and preserves the target.
- A completed object transition increments `object_revision`. Repeating a completed cleanup is a
  no-op. Unexpected revisions, conflicting rotation wraps, or missing target wraps fail closed.

The journal cleanup marker is written only after every captured object is clean. If a process stops
between object updates, recovery accepts reachable partial cleanup states and a retry completes the
remaining objects.

### MongoDB boundary

Mongo encrypted-object stage and cleanup replace a document only when record ID, storage schema,
and current `object_revision` still match. The Mongo rotation collection has an immutable unique
rotation ID, at most one `prepared` entry per AID, and status/cleanup compare-and-swap transitions.
Live MongoDB 8.3.4 verification covers successful transitions, stale filter rejection, and
persistence after client and server restart.

This is per-document conditional integrity. It is not a transaction spanning registration,
journal, and multiple encrypted objects, and it does not prove multi-process linearizability.

## Failure behavior

- Missing or changed store: `owner_store_not_attached` or `owner_store_id_conflict`.
- Object-set drift: `owner_rotation_object_set_changed`.
- Impossible restored combination: `rotation_recovery_state_invalid`.
- Stale cleanup object revision: `owner_object_revision_conflict`.
- Unknown or non-terminal cleanup: `rotation_not_found` or `rotation_not_terminal`.
- Stale Mongo journal transition: `rotation_state_conflict`.

All failures preserve the currently authoritative registration and do not silently select a
different owner wrap.

## Consequences and limitations

The prototype can resume a prepared rotation after a JSON-backed Provider restart and can recover
partial terminal cleanup by retrying it. Terminal history is auditable instead of process-local.
The cost is a larger JSON state document and strict coupling to stable store IDs.

The journal does not store private keys, plaintext DEKs, or plaintext data. The prototype still
uses toy PRE/HPKE backends, static local management authentication, and no distributed transaction
coordinator. Those boundaries remain explicit non-claims.

## Verification

- `test_rotation_recovery.py`: pending restart, durable commit, abort cleanup, idempotency, and
  corrupt-journal rejection.
- `test_owner_key_rotation.py`: CORE-003 prepare/stage/commit and partial-abort compatibility.
- `test_mongodb_rotation_cas.py`: live object revision CAS, journal state CAS, cleanup, and
  reconnect persistence.
- One full regression is required because the Provider persistence schema and owner-store protocol
  changed across core modules.
