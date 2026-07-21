# P2 attack matrix report

## Scope

P2 extends the PRE-SAGA security experiment matrix from four attacks to eight
attacks. The goal is to test whether the data layer adds enforceable protection
after SAGA-compatible contact authorization has already allowed communication.

## Added attacks

| Attack | Enforcement point | Expected result |
|---|---|---|
| `stale_rekey_use` | Data token version binding | Old token/rekey material cannot be used for a newer version request. |
| `provider_plaintext_probe` | PRE proxy visibility boundary | Provider can transform encrypted DEKs but does not observe plaintext DEK or plaintext data. |
| `metadata_linkage_probe` | Data token record scope | A contact-allowed requester cannot use a token to probe records outside bound scope. |
| `compromised_requester_exfiltration` | Data class and purpose binding | A compromised requester cannot broaden a valid token into another data class or exfiltration purpose. |

## Acceptance check

- `experiments/attacks/run_all.py` now emits eight rows in
  `results/tables/security_matrix.csv`.
- `tests/security/test_attack_scripts.py` checks all eight attack names and
  asserts that each one is blocked after contact authorization is allowed.

## Boundary statement

These tests do not claim to solve every endpoint-compromise or metadata-privacy
problem. In particular, once an authorized requester legitimately decrypts data,
pure cryptography cannot prevent that endpoint from copying the plaintext. P2
therefore tests bounded exfiltration attempts: attempts to broaden data class,
record scope, purpose, version, or token use after contact authorization.
