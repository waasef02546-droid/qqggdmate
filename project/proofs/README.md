# PRE-SAGA Formal Analysis Artifacts

## Scope

These files provide ProVerif-style symbolic models for the PRE-SAGA stage 4 analysis.

They are not a proof of a new proxy re-encryption primitive. They model the protocol-level security boundary:

- data tokens are bound to owner, requester, record, data class, purpose, version, expiration, and requester key;
- Provider / PRE Proxy can transform an owner-wrapped encrypted DEK into a requester-wrapped encrypted DEK;
- Provider should not learn the plaintext DEK;
- a requester mismatch should be rejected before transform.

## Files

| File | Goal |
|---|---|
| `presaga_dek_secrecy.pv` | Model that the Provider / attacker cannot learn `dek` without requester authorization. |
| `presaga_rekey_authentication.pv` | Model that requester, purpose, record, and version bindings are checked before re-encryption. |

## Current Status

The local repository includes smoke tests that check the artifacts contain the expected queries, events, and boundary statements. Running ProVerif itself is a later environment-dependent step.

## Boundary

The model does not cover:

- endpoint compromise;
- plaintext leakage after legitimate requester decryption;
- metadata privacy against Provider;
- implementation memory safety;
- security of the toy PRE backend.
