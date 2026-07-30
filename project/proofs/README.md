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
| `presaga_token_secrecy.pv` | Model that data token acceptance implies matching token issuance. |
| `presaga_dek_secrecy.pv` | Model that the Provider / attacker cannot learn `dek` without requester authorization. |
| `presaga_rekey_authentication.pv` | Model that requester, purpose, record, and version bindings are checked before re-encryption. |

## Current Status

The local repository includes smoke tests that check the artifacts contain the expected queries, events, and boundary statements.

P4 adds `run_proverif.py`, which attempts to execute every `.pv` model with the local `proverif` executable and writes reproducible outputs under `results/proofs/`. If ProVerif is not installed, the runner records `tool_unavailable` instead of claiming a successful proof run.

```powershell
python -m proofs.run_proverif
```

## Linkage with implementation stages

| Stage | Formal-analysis linkage |
|---|---|
| P1 SAGA-compatible adapter | `presaga_token_secrecy.pv` models that accepted data-token use must correspond to issued token fields. |
| P2 attack matrix | `presaga_rekey_authentication.pv` maps requester, record, data class, purpose, version, and key binding to mismatch/stale-token attacks. |
| P3 task-level evaluation | `presaga_dek_secrecy.pv` states the Provider/PRE Proxy visibility boundary used by the plaintext-probe and evaluation reports. |

## Boundary

The model does not cover:

- endpoint compromise;
- plaintext leakage after legitimate requester decryption;
- metadata privacy against Provider;
- implementation memory safety;
- concrete security of `nucypher-core`, the Umbral adapter, or the retained
  toy/stub fixtures.
