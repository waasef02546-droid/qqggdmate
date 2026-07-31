# Current milestone

## Active work package

- ID: `KEYCUSTODY-001`
- Title: Authenticated owner/KMS rewrap boundary
- State: `acceptance_review`
- Authorization date: `2026-07-31`
- Objective: remove owner source private keys and plaintext DEKs from the Provider rotation
  request/call graph. The Provider must export a deterministic, non-secret rewrap request and
  accept only an owner/KMS-produced artifact signed by the authoritative source owner key and
  bound to the exact rotation, store, record, object revision, registrations, contexts, backend,
  source wrapper, and target wrapper.
- Protected assets: owner source private keys, plaintext DEKs, and correctness of the active
  owner-wrapped DEK during rotation.
- Attacker/error model: malformed or replayed artifacts, cross-record/cross-rotation substitution,
  target-key substitution, stale object revisions, wrong owner keys, interrupted delivery, service
  restart, and a caller holding the prototype management Bearer token but not the source owner key.
- Failure behavior: fail closed before object mutation or registration commit, preserve the active
  source wrap, emit a stable reason, and permit safe retry of the exact valid artifact.

## Scope

- Primary implementation paths:
  - `project/presaga/crypto/key_custody.py`
  - `project/presaga/crypto/pre_interface.py`
  - `project/presaga/crypto/umbral_pre.py`
  - `project/presaga/provider/app.py`
  - `project/presaga/provider/registry.py`
  - `project/presaga/provider/server.py`
  - `project/presaga/storage/encrypted_store.py`
  - `project/presaga/storage/mongo_encrypted_store.py`
  - focused rotation, recovery, HTTP, Mongo, security, and release tests
- Core mechanism:
  1. Provider derives a canonical public `OwnerRewrapRequest` from live registry, journal, store,
     provenance, and revision state.
  2. An owner/KMS-side custodian requires a separately supplied owner-local approval for the exact
     rotation, record, revision, and target key; it then unwraps and freshly rewraps the DEK
     outside the Provider boundary and signs the request/target-wrapper digests.
  3. Provider reconstructs the request, verifies the signature against the journal-bound active
     source registration, validates the target Umbral wrapper key/context, and stages it with the
     existing object-revision CAS.
  4. Exact artifact replay is idempotent; altered or stale artifacts fail closed.
- KFrag-scope decision: a later `KFRAGSCOPE-001` should use label-derived, per-record-version
  delegating keys held by owner/KMS. `nucypher-core==0.15.0` does not implement native
  label-bound PRE; this work package does not claim or implement that property.

## Non-goals

- production HSM/KMS certification, remote attestation, mTLS, secure-memory zeroization, or
  side-channel resistance;
- a whole-process malicious-Provider confidentiality theorem;
- implementing per-record delegating keys or eliminating retained-KFrag collusion in this package;
- changing Contact/data-policy semantics, ProVerif models, multi-object transaction boundaries,
  leader election, or distributed linearizability;
- automatic migration of legacy ToyPRE/HPKE wraps or in-progress legacy rotations.

## Orchestration

- Primary agent owns scope, architecture, integration, test selection, evidence, and final
  acceptance.
- Three bounded read-only subagent audits cover the private-key call graph, KFrag-scope design,
  and independent acceptance/evidence requirements.
- One writer owns every overlapping core area; no parallel edits to Provider/storage files.

## Acceptance criteria

- The Provider HTTP schema, management facade, registry, stores, and generic backend interface no
  longer accept `source_private_key` or call decrypt-and-rewrap.
- A versioned canonical request and signed artifact bind all listed rotation and object fields;
  the verification key comes from the authoritative source registration, never from the artifact.
- Umbral target wrappers are publicly validated for suite, format, target key, and target context
  before CAS staging.
- Normal prepare/export/custody/stage/commit/cleanup succeeds and the target owner decrypts.
- Wrong source key, forged/tampered artifact, target substitution, cross-record/rotation replay,
  stale revision, malformed wrapper, and conflicting retry are denied without changing the source
  wrap or making commit possible.
- Exact valid artifact retry is idempotent, including after interrupted response delivery.
- JSON and live Mongo restart recovery, object CAS, journal CAS, abort, cleanup, and stale-writer
  fencing remain valid; Mongo evidence must not skip.
- Provider-visible state, journal, audit, errors, and release artifacts contain no raw/base64/hex
  source private key or plaintext DEK.
- Focused verification, one justified full regression, a clean-input authoritative release, the
  independent verifier, and an independent final acceptance audit pass.

## Evidence obligations

- Use `docs/verification/reviews/KEYCUSTODY-001-acceptance.md` as the live checklist and final
  acceptance record.
- Add an ADR for the custody protocol, key-use compromise, compatibility, recovery, and KFrag
  route decision.
- Update claims C-003, C-006, C-007, and C-008, traceability, protocol, paper, release gates, and
  limitations without exceeding the tested process boundary.
- Record all targeted, failed, Mongo, full-regression, release, and closure runs in the ledger.

## Risks

- The prototype reuses the source Umbral secret key for a domain-separated custody attestation;
  production deployment should register a separate KMS attestation key before rotation.
- The owner/KMS process still materializes the source key and DEK; this package moves that exposure
  out of Provider, not out of all memory.
- The approval JSON is trusted owner-local input; it is matched exactly but not signed or
  operating-system-attested by this prototype.
- Recovery trusts repository integrity and restores a previously verified wrapper/digest; it does
  not persist and re-verify the custody signature at restart.
- A copied old KFrag/ciphertext remains usable within its old owner/requester key-pair scope.
- Multi-object rotation remains a recoverable sequence, not a distributed transaction.
- Unrelated user drafts and untracked frontend/history material must remain unstaged unless an
  exact file is deliberately updated for this work package.

## Previous accepted work packages

- `CRYPTO-001`: concrete versioned Umbral backend, authoritative owner/requester binding,
  exposed-state Provider regression, clean release, and independent acceptance.
- `REL-001`: authoritative experiment provenance, release manifest, verifier, ProVerif, and Mongo.
- `CORE-005`: recoverable JSON/Mongo Provider service and stale-writer fencing.
- `CORE-004`: persistent rotation history, recovery, cleanup, and Mongo conditional updates.
- `CORE-003`: owner-wrap provenance and prepare/stage/commit-or-abort rotation lifecycle.
- `CORE-002`: authenticated AID registration and management/data-plane separation.
- `CORE-001`: Contact-to-data-token-to-re-encryption server binding.

## Proposed next work package

- Candidate ID: `KFRAGSCOPE-001`
- Candidate topic: label-derived per-record-version Umbral delegating keys and a direct retained-
  KFrag cross-record attack gate.
- State: `not_authorized`
- Rule: do not begin until `KEYCUSTODY-001` is accepted and the user authorizes it.
