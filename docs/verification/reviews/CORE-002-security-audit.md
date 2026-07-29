# CORE-002 independent security audit

- Date: 2026-07-28
- Method: three parallel read-only agents for protocol boundaries, registry/storage, and evidence
- Write ownership: primary agent only

## Pre-implementation findings

Two P0 gaps were independently confirmed:

1. `AgentRegistry` was write-only for security decisions. Issuance hashed the caller-supplied key,
   while consumption compared the token with the same caller-supplied request.
2. Registration was unauthenticated last-writer-wins, and management/data routes shared one HTTP
   handler without an authentication boundary.

P1 gaps included no lifecycle/version/status model, no CAS, schema-less restore, unconditional
Mongo upsert, and no rotation/revocation invalidation. The audit also identified a claim boundary:
toy PRE cannot authenticate the target of opaque rekey bytes.

## Implemented resolution

- Versioned, domain-separated AID/key fingerprints with create/replace/revoke lifecycle
- Original-manager and exact-version checks with process-local CAS
- Durable revocation tombstones and legacy-unverified quarantine
- Separate in-process management capability and data facade
- Bearer-authenticated `/v1/management/*` HTTP routes; old routes removed
- Registry-derived token binding and re-resolution during consumption
- JSON schema v2 validated restore and Mongo insert/expected-version persistence
- Migrated runtime and experiment setup paths

## Verification review

Focused coverage maps directly to the changed behavior rather than repeating unrelated assertions:

- positive: create v1, authoritative issuance, current-version consumption, restart;
- negative: wrong key, wrong manager, duplicate, unknown, revoked, stale token, missing HTTP auth;
- boundary: malformed AID/key, fingerprint corruption, legacy record;
- concurrency: one winner for competing expected-version replacements;
- regression: all discovered tests in an isolated copy after copying required SAGA evidence.

No core test was rerun after the final passing focused and full-regression states. Mongo behavior is
not accepted as runtime-verified because the local service was unavailable.

## Residual risks

- Management separation is in-process plus a static HTTP Bearer secret, not deployment isolation.
- The registry lock and token lock do not provide multi-process transactions.
- Mongo conditional replacement code is not runtime-verified in this environment.
- Owner-key rotation, encrypted-object provenance, and rewrap migration are not implemented.
- Toy PRE/HPKE limitations remain unchanged; rekey-target authentication is not claimed.

No unresolved P0 or P1 remains inside the bounded CORE-002 requester-registration claim. The owner
rotation and distributed-persistence items are explicit non-claims, not silently accepted behavior.
