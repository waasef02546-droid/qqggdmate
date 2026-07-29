# ADR 0004: Bind owner-wrapped DEKs to registrations and stage key rotation

- Status: Accepted for CORE-003; persistence/recovery limitations are superseded by ADR 0005
- Date: 2026-07-28
- Work package: `CORE-003`
- Claim mapping: proposed `C-007`; do not broaden `C-003` or `C-006`

## Context

CORE-002 made requester-token decisions derive from an authenticated, versioned `AgentRecord`.
Owner-side encrypted-object writes did not receive the same protection. `StoredObject` records only
the data record, ciphertext, and owner-wrapped DEK; both in-memory and Mongo stores accept a raw
owner public key from their caller. The re-encryption data plane likewise accepts raw
`encrypted_dek_owner` and opaque `rekey` bytes instead of resolving the authoritative stored
object.

Immediate owner-registration replacement therefore has two unsafe outcomes. Existing wrapped DEKs
may become undecryptable under the new owner key, while old wrapped DEKs and old-key rekeys may
continue to be transformed without any stored evidence that they belong to the intended owner
registration. The existing stale-rekey experiment changes a data-record version; it is not evidence
for owner identity-key rotation.

## Decision

### Stored provenance

Every newly written encrypted object must derive its owner wrapping key from an active
authoritative `AgentRecord`. A caller cannot supply or override the raw owner public key. The
persisted object schema contains:

- `stored_object_schema_version`;
- `owner_aid`;
- `owner_key_fingerprint`;
- `owner_registration_version`;
- `owner_registration_id`;
- `owner_key_algorithm`;
- `encrypted_dek_owner`;
- the existing authenticated ciphertext and `DataRecord`; and
- an optional staged wrap and rotation reference during an in-progress rotation.

The owner AID in the provenance must equal `DataRecord.owner_aid`. Fingerprint, registration
version, registration identifier, and key algorithm must equal one internally consistent active
registration. These fields are security data, not descriptive metadata.

Legacy objects without the complete provenance tuple are `legacy_unverified`. Malformed,
unsupported, or internally inconsistent objects are quarantined. Neither state may reach PRE
transformation. Migration requires an authenticated management operation that proves the source
registration and successfully unwraps and rewraps the DEK; filling fields from an AID alone is not
a valid migration.

### Authoritative write and consumption paths

Encrypted-store construction receives a registration resolver or an equivalent trusted capability.
`put(record, plaintext)` resolves the active owner registration inside the store and records the
derived provenance. The insecure `put(..., owner_public_key)` and `put_payload(...,
owner_public_key)` compatibility paths are removed rather than silently retained.

The re-encryption data plane identifies an authoritative stored object by record ID. It does not
accept a caller-selected owner-wrapped DEK. The Provider/store resolves the object, validates its
record binding and owner provenance, selects the wrap for the active owner registration, and only
then invokes PRE.

All provenance and lifecycle checks occur before `DataToken.remaining_uses` is decremented. A
missing, legacy, malformed, stale, revoked, mismatched, or rotation-conflicted owner wrap denies
without consuming the token or calling the backend.

### Prepare, stage, commit, and abort

An owner-key rotation is an authenticated management operation with an immutable `rotation_id`,
owner AID, management actor, exact source registration ID/version/fingerprint, proposed target
key/fingerprint/algorithm, target registration version, target object IDs, timestamps, state, and
per-object outcome.

The lifecycle is:

```text
active(Kn)
  -> prepared(Kn, Kn+1)
  -> staging(Kn active; Kn+1 wraps accumulated non-destructively)
  -> staged(all target objects have verified Kn+1 wraps)
  -> committed(Kn+1 active)
```

From `prepared`, `staging`, `staged`, or `failed`, an authorized actor may abort:

```text
prepared|staging|staged|failed -> aborted(Kn remains active)
```

1. **Prepare** authenticates the original management principal, requires the exact active
   registration version, derives the target fingerprint, allocates `rotation_id`, snapshots the
   owner object set, and creates a pending registration. It does not replace the active
   registration.
2. **Stage/rewrap** runs at the owner/store boundary. The old private key unwraps the DEK and the
   pending public key wraps it again. The Provider/PRE proxy neither receives nor persists the
   plaintext DEK. The new wrap is stored beside the old wrap with target provenance and a
   conditional expected-source check.
3. **Commit** is allowed only when every target object has a verified staged wrap, no per-object
   failure remains, the active source registration and target snapshot still match, and the actor
   and expected version are valid. Activation is the final state change. After activation, the
   data plane selects only the wrap matching the new active registration.
4. **Abort** is idempotent. It removes or marks unusable the pending registration and staged wraps
   while leaving the old registration and old wraps active.

The prepared object inventory is frozen. A write during preparation changes the observed object
set and makes commit fail closed with `owner_rotation_object_set_changed`; this prototype does not
yet reject the write at its entry point. A zero-object rotation may commit after the same
actor/version checks. Repeated or conflicting transitions fail explicitly.

### Partial failure, crash, and concurrency

Staging is non-destructive: the old wrap remains usable while the old registration is active. A
backend, persistence, or validation failure records the object ID and reason, moves the rotation to
`failed`, and forbids commit until the failure is explicitly retried successfully or the rotation
is aborted.

In memory, an owner-scoped lock serializes prepare, object-set mutation, commit, abort, and
consumption's provenance snapshot. Competing expected-version mutations have one winner.
Consumption racing commit must observe either the complete old active state, the complete new
active state, or a fail-closed rotation conflict; it must never transform a wrap from one state
under the other state's provenance.

At CORE-003 acceptance, the implemented prepared-rotation journal was process-local. JSON Provider
persistence stored registrations and tokens but not encrypted objects or prepared rotations.
Restart/resume and crash recovery were therefore outside that accepted claim. ADR 0005 records the
subsequent persistent recovery design.

Mongo stores the same provenance and rotation journal, and every stage/commit update uses
registration version, rotation ID, object ID, and source fingerprint as conditional filters.
Activation occurs only after all staged-object checks. Without an actual Mongo transaction or a
single-writer lease, this is not a distributed atomic commit or crash-safety guarantee. A mixed,
missing, or uncertain restored state fails closed and requires management recovery. CORE-003 may
claim Mongo lifecycle behavior only after a real Mongo run; otherwise the Mongo criterion remains
blocked and the claim must say so.

## Failure behavior

- Unknown, revoked, or legacy owner: `owner_registration_not_active`.
- Raw owner key or raw owner-wrapped DEK supplied through the data plane:
  `owner_key_override_forbidden`.
- Missing or legacy object provenance: `owner_provenance_unverified`.
- Malformed or unsupported provenance: `owner_provenance_invalid`.
- Provenance does not match the record or active registration: `owner_provenance_mismatch`.
- Object remains bound to a prior registration after activation: `owner_registration_stale`.
- Wrong management actor: `rotation_actor_forbidden`.
- Stale registration/rotation expectation: `rotation_version_conflict`.
- A second active rotation or a write during rotation: `rotation_in_progress`.
- Incomplete or failed staging: `rotation_not_ready`.
- Unknown or illegal transition: `rotation_state_conflict`.
- Uncertain persistent state: `rotation_recovery_required`.

## Alternatives rejected

- Persisting only the owner AID: it does not identify the key or registration version used to wrap
  the DEK.
- Trusting provenance fields supplied with an HTTP transform request: the caller could keep a
  forged tuple self-consistent.
- Replacing the owner registration before rewrapping: it creates an availability and provenance
  gap.
- Overwriting old wraps while staging: a partial failure could make already processed objects
  unrecoverable.
- Automatically trusting legacy objects: their owner-key origin is unknown.
- Rewrapping inside the Provider/PRE proxy: the toy adapters would expose plaintext DEKs to the
  component covered by the Provider non-observation claim.

## Consequences and limitations

- Store, Provider, HTTP, agent-runtime, experiment, and persistence APIs must migrate away from raw
  owner keys and raw owner-wrapped DEKs.
- Rotation temporarily stores two wrapped forms of the same DEK. Old wraps may be removed only by
  an explicit post-commit cleanup after recovery requirements are satisfied.
- The single-process lock and JSON atomic replacement do not establish distributed transaction
  safety.
- Mongo conditional writes are a fail-closed prototype boundary, not proof of multi-process
  linearizability or crash-safe distributed rotation.
- Toy PRE and HPKE-shaped backends are insecure test doubles. Successful control-flow checks do not
  prove rekey target authenticity, secure key erasure, side-channel resistance, or production
  cryptographic security.
- Owner-side unwrap/rewrap necessarily handles plaintext DEK in the trusted owner/store boundary.
  The bounded claim is that the Provider/PRE proxy does not receive it, not that plaintext DEK
  never exists in process memory.
- Existing formal artifacts model static transform authorization and do not prove this lifecycle,
  persistence recovery, or concurrency behavior.

## Verification required before acceptance

The bounded in-memory implementation and v2 Mongo serialization/CAS path were implemented in
CORE-003. Focused verification and one isolated full regression passed; the Mongo lifecycle test
was skipped because no local MongoDB service was available. ADR 0005 and CORE-004 provide the
subsequent persistence, cleanup, recovery, and live-Mongo evidence.

- Positive: authoritative write provenance, normal transform, complete prepare/stage/commit, and
  decryptability under the new owner key.
- Negative: raw-key/EDEK override, unknown/revoked/legacy owner, tampered or stale provenance, old
  wrap/rekey after commit, wrong actor/version, and incomplete commit.
- Boundary: zero and one-object rotations, repeated/idempotent operations, writes during rotation,
  abort before and after partial staging, unsupported algorithms, and object deletion conflicts.
- Concurrency: competing prepare/commit, write versus rotation, consume versus commit, and rewrap
  failure, with token non-consumption on provenance denial.
- Persistence: valid and corrupt JSON round trips, restart/resume/abort, committed restart, legacy
  quarantine, and equivalent Mongo checks on an available service.
- Regression: one isolated full regression is justified only after focused checks pass because the
  store schema and Provider/HTTP APIs are cross-cutting.
