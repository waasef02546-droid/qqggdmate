# PRE-SAGA Proof--Code--Experiment Traceability Matrix

## Purpose and reading rule

This matrix binds each paper-level security claim to (1) a symbolic-model event
or query, (2) the prototype schema and enforcing code path, and (3) a
repeatable test or experiment.  It is evidence of *prototype conformance to
the stated model boundary*, not a proof that the toy PRE backend is a secure
concrete PRE construction.

The authoritative formal files are under `proofs/`.  Code references below are
repository-relative to `project/`; test and experiment commands are run from
the `project/` directory.

## Matrix

| ID | Formal event / query | Bound protocol fields | Enforcing implementation | Repeatable evidence | Paper claim and boundary |
|---|---|---|---|---|---|
| T1 data-token authenticity | `presaga_token_secrecy.pv`: `DataTokenAccepted(...) ==> DataTokenIssued(...)` | `DataToken.owner_aid`, `requester_aid`, `allowed_record_ids`, `allowed_data_classes`, `purpose`, `min_version`, `max_version`, `requester_public_key_hash`, `issuer_signature` | `presaga/protocol/schemas.py:DataToken`; `presaga/provider/token_service.py:TokenService.issue_data_token`, `validate`, `_sign` | `tests/unit/test_token_service.py`; `tests/security/test_formal_artifacts.py`; `python -m proofs.run_proverif` | An accepted prototype data token is issuer-integrity protected and bound to the stated owner/requester/scope/purpose/version/key fields. This does not establish a production token-signature scheme beyond the prototype HMAC issuer boundary. |
| T2 DEK secrecy from Provider | `presaga_dek_secrecy.pv`: `query attacker(secret_dek)`; `TransformIssued(...) ==> PolicyAllow(...)` | owner/requester/record/class/purpose/version in the symbolic `rekey` and `enc_dek` terms; audit booleans `provider_saw_plaintext_dek`, `provider_saw_plaintext_data` | `presaga/provider/pre_proxy.py:PREProxy.transform`; `presaga/provider/audit.py:AuditLogger.record`; `presaga/protocol/schemas.py:AuditEvent`; AES envelope API in `presaga/crypto/envelope.py` | `experiments/attacks/provider_plaintext_probe.py`; `tests/security/test_attack_scripts.py`; `tests/unit/test_crypto_envelope.py` | The Provider/PRE proxy transforms the encrypted DEK and records no plaintext DEK/data observation in the prototype. This is a symbolic/architectural boundary, not protection against a malicious or memory-compromised Provider. |
| T3 re-encryption authentication | `presaga_rekey_authentication.pv`: `TransformAccepted(...) ==> TokenIssued(...)`; `TransformRejected(...)` | token requester, record, class, purpose, version, requester-key hash | `presaga/provider/token_service.py:TokenService.validate`; `presaga/provider/pre_proxy.py:PREProxy.transform` | `tests/unit/test_token_service.py`; `tests/integration/test_normal_sharing.py`; `experiments/attacks/requester_mismatch.py`; `experiments/attacks/stale_rekey_use.py` | A transform is attempted only after the data token validates against the present request. The toy key-transform primitive itself is outside this authentication claim. |
| T4 policy denial after contact authorization | `presaga_rekey_authentication.pv`: mismatched `data_token(...)` terms emit `TransformRejected(...)` rather than `TransformAccepted(...)` | `DataSharingPolicy.requester_selector`, `data_scope`, `purposes`, `validity`, `version_constraints`; matching fields in `DataAccessRequest` | `presaga/provider/data_policy.py:DataPolicyEvaluator.evaluate`, `_match`; `presaga/protocol/schemas.py:DataSharingPolicy`, `DataAccessRequest` | `tests/unit/test_data_policy.py`; `experiments/attacks/unauthorized_data_class.py`; `experiments/attacks/purpose_mismatch.py`; `tests/security/test_attack_scripts.py` | A SAGA-compatible contact allow is insufficient for data access: an unauthorized class, requester, record, purpose, or version is denied by PRE-SAGA policy. This does not prevent a legitimate requester from leaking already decrypted plaintext. |
| T5 replay prevention | No standalone replay query; it refines the accepted-use condition by preventing a second `TransformAccepted` after token consumption. | `DataToken.max_uses`, `remaining_uses`, signed token state | `presaga/provider/token_service.py:TokenService.validate`, `consume`; `presaga/provider/pre_proxy.py:PREProxy.transform` | `experiments/attacks/token_reuse.py`; `tests/security/test_attack_scripts.py`; `tests/unit/test_token_service.py` | A one-use data token is rejected on replay after a successful transform. Multi-process atomicity and distributed replay resistance require the persistent Provider deployment path and remain separate engineering work. |

## Executable traceability guard

`tests/security/test_traceability.py` is intentionally structural: it checks
that every formal artifact, code path, test/experiment reference, and required
schema field named in this matrix remains present. It cannot prove runtime
semantic equivalence; it prevents silent documentation drift when the prototype
is reorganized.

```powershell
python -m unittest tests.security.test_traceability -v
python -m unittest tests.security.test_formal_artifacts tests.security.test_attack_scripts -v
python -m proofs.run_proverif
```

When ProVerif is unavailable, the last command records `tool_unavailable` under
`results/proofs/`; this must be reported as unavailable rather than as a proof
success.

## Non-goals retained by this matrix

- Concrete security of `presaga.crypto.toy_pre` or `hpke_kem_stub`.
- Endpoint compromise, post-decryption exfiltration, and Provider metadata privacy.
- Memory safety, side channels, and distributed transaction/locking guarantees.
- Full behavioural equivalence between the symbolic model and every deployment.
