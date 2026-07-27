# ADR 0002: Bind data-token issuance and PRE consumption to one Contact session

- Status: Accepted
- Date: 2026-07-26
- Work package: `CORE-001`
- Claim mapping: `C-001`, `C-005`

## Context

The earlier prototype kept Contact authorization in the agent runtime while the Provider could issue
a DataToken from a data-policy decision alone. The DataToken did not identify the Contact session
that preceded it, and PRE consumption validated and decremented the token in separate operations.
Consequently, security depended on client call order, a Contact session could not be revalidated at
consumption, and concurrent requests could race a one-use budget.

The protected action is Provider transformation of an owner-encrypted data key for a requester.
Within the data plane, the attacker may call Provider endpoints directly, replay requests
concurrently, possess another valid Contact session for the same identities, or tamper with
serialized tokens. The prototype trusts the Provider issuer secret, its server-side token state, a
trusted management plane, and authenticated AID assertions supplied by the surrounding transport.
The current dependency-free HTTP adapter does not implement that management or identity
authentication and must not be exposed as a production security boundary. Distributed Provider
instances and Contact revocation are also outside this decision.

## Decision

1. The authoritative data-token issuance operation accepts a Contact token, validates its signature,
   time window, owner, and requester, then evaluates the separate data policy.
2. `DataToken` contains `contact_token_id` and `contact_session_ref`. Both fields are covered by the
   existing issuer signature.
3. Data-token expiry is the earlier of data-policy expiry and Contact-token expiry.
4. The HTTP API requires `contact_token_id` when requesting a DataToken and resolves that identifier
   only from server-side Contact state.
5. At re-encryption, the server resolves the Contact token named by the signed DataToken; the client
   cannot substitute a different session identifier. The PRE proxy revalidates the Contact token
   before transformation.
6. Data-token validation and use-budget decrement execute under one process-local reentrant lock.
   Concurrent replays of a one-use token therefore receive at most one successful authorization.
7. Persisted legacy DataTokens without the two binding fields are restored with empty bindings and
   fail closed at re-encryption.

## Failure behavior

- Missing Contact at issuance: `contact_session_required`.
- Unknown bound Contact: `contact_session_not_found`.
- Forged Contact: `contact_token_signature_invalid`.
- Expired Contact: `contact_token_expired`.
- A different valid session: `contact_session_mismatch`.
- Concurrent attempts after the allowed budget: `token_exhausted`.

Denials are recorded by the PRE audit path and do not expose plaintext data or plaintext data keys.

## Alternatives rejected

- Agent-cache checks alone: not authoritative because a caller can bypass the agent runtime.
- Binding only owner/requester identities: two valid sessions for the same identities would remain
  interchangeable.
- Separate validation and decrement: vulnerable to check-then-use races under the threaded HTTP
  server.
- Silently accepting legacy unbound tokens: would preserve the original authorization gap.

## Consequences and limitations

- In-process and HTTP callers must provide Contact context when requesting a DataToken.
- Previously issued unbound DataTokens no longer authorize re-encryption.
- HTTP agent registration, rulebook, policy, and Contact-session endpoints are prototype adapters
  without authentication. Security claims assume those operations receive trusted, authenticated
  identities and management input.
- Consumption occurs before the PRE backend call. Backend failure fails closed but spends one use.
- The lock protects one Python Provider process only. A distributed deployment needs a transactional
  shared token store or equivalent compare-and-swap operation.
- No Contact revocation service is added; validation covers signature, identities, exact session,
  and expiry.

## Verification

- Focused acceptance covers missing, forged, expired, session-substitution, legacy-unbound,
  persisted replay, concurrent-replay, normal lifecycle, HTTP persistence, and attack paths.
- Isolated full regression: 59 tests total; 58 passed and the MongoDB E2E test was skipped because
  local MongoDB was unavailable.
- Commands and environments are retained in `docs/verification/test-ledger.yaml`.
