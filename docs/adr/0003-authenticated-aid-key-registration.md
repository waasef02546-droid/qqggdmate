# ADR 0003: Authenticate and version AID-to-key registration

- Status: Accepted
- Date: 2026-07-28
- Work package: `CORE-002`
- Claim mapping: `C-005`, `C-006`

## Context

The earlier Provider registry stored only `{aid, public_key}` and silently overwrote duplicate
AIDs. More importantly, token issuance hashed the key supplied by the data request, and
re-encryption compared the token only with the same caller-supplied request. The registry was
therefore irrelevant to security decisions: an allowed AID could select an arbitrary key and keep
that self-selected pair consistent across issuance and consumption.

The standalone HTTP server also exposed agent registration, rulebook changes, policies, Contact
sessions, token issuance, and re-encryption under one unauthenticated route family. JSON restore
wrote raw legacy records directly into the registry, and Mongo used unconditional upsert.

## Decision

1. A canonical AID is bound to one `AgentRecord` containing the public key, a domain-separated
   SHA-256 fingerprint, registration version, status, management principal, immutable registration
   identifier, timestamps, and prototype key-algorithm identifier.
2. Initial creation is version 1 and rejects any existing AID, including a revoked tombstone.
3. Replacement and revocation require the original management principal and an exact
   `expected_version`. A successful mutation increments the version exactly once under a
   process-local lock; concurrent stale writers fail.
4. Revocation creates a durable tombstone. Physical deletion and implicit re-registration are not
   security-path operations.
5. `PREProviderApp` is the data-plane facade. Registration, rulebook, and data-policy mutations
   exist only on its separate `TrustedManagementPlane` capability.
6. HTTP management operations move under `/v1/management/*` and require a constant-time checked
   Bearer token. The previous `/v1/agents`, `/v1/contact-rulebooks`, and `/v1/data-policies` routes
   are absent.
7. Token issuance resolves owner and requester from the active server registry. The request key is
   optional compatibility input and, when present, is only an equality assertion.
8. The signed `DataToken` carries the resolved requester fingerprint and registration version.
   Consumption re-resolves active owner/requester registrations and rejects rotation, revocation,
   unknown AID, legacy state, or fingerprint/version mismatch before PRE.
9. JSON state is schema version 2. Legacy registrations are imported as `legacy_unverified` and
   cannot authorize data operations. Restore recomputes and validates fingerprints.
10. Mongo initial registration uses insert semantics, while replacement has an
    expected-version filter; Mongo runtime verification remains conditional on an available local
    service.

The fingerprint is:

```text
SHA-256("PRE-SAGA-AID-KEY-V1\0" || key_algorithm || "\0" || canonical_public_key_bytes)
```

## Failure behavior

- Duplicate create: `registration_exists`.
- Unknown AID: `registration_not_found`.
- Revoked or legacy record: `registration_not_active`.
- Wrong management principal: `registration_actor_forbidden`.
- Stale replacement/revocation: `registration_version_conflict`.
- Caller key assertion mismatch: `requester_key_mismatch`.
- Token bound to a replaced registration: `requester_registration_stale`.
- Missing/wrong HTTP management credential: `management_authentication_required`.

## Alternatives rejected

- Hashing only the request key: caller-controlled and does not authenticate the AID binding.
- Silent last-writer-wins replacement: permits takeover and makes concurrency results order
  dependent.
- Physical deletion: permits accidental resurrection and loses revocation evidence.
- Automatically trusting legacy `{aid, public_key}` files: provenance and management authority are
  unknown.
- Adding another GitHub MCP/token surface: duplicates the installed GitHub plugin without improving
  this protocol invariant.

## Consequences and limitations

- Existing experiment and runtime setup code must use the explicit management capability.
- Old tokens and unauthenticated legacy registrations fail closed.
- Replacing or revoking a requester invalidates previously issued tokens immediately.
- The HTTP Bearer token and in-process capability establish a prototype management boundary, not
  production identity, mTLS, HSM, or distributed authorization.
- JSON persistence is single-process and protected only by local locks plus atomic replacement.
- The toy PRE/HPKE backends still cannot prove that opaque rekey bytes target the registered key.
  The verified claim is server-enforced control-flow binding, not production cryptography.
- Owner encrypted-object key provenance and safe ciphertext rewrapping across owner rotation remain
  future work; CORE-002 does not claim them.

## Verification

- Registry unit checks cover fingerprinting, validation, duplicate/unknown denial, actor and
  version checks, concurrent CAS, tombstones, corrupt restore, and legacy quarantine.
- Management/data-plane integration checks cover interface separation, server-derived issuance,
  caller-key forgery, rotation/revocation invalidation, and JSON restart.
- HTTP integration checks cover Bearer authentication, removal of the old management route, normal
  issuance/transform, and replay after restart.
- Focused result: 31 tests passed.
- Isolated full regression: 73 tests total; 72 passed and one MongoDB test was skipped because no
  local MongoDB was listening.
