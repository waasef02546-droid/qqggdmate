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
| T1 data-token authenticity | `presaga_token_secrecy.pv`: `DataTokenAccepted(...) ==> DataTokenIssued(...)` | The symbolic model carries owner/requester/record/class/purpose/version. Runtime signing additionally covers `allowed_record_ids`, `allowed_data_classes`, `min_version`, `max_version`, `requester_public_key_hash`, registration fields, and `issuer_signature`. | `presaga/protocol/schemas.py:DataToken`; `presaga/provider/token_service.py:TokenService.issue_data_token`, `validate`, `_sign` | `tests/unit/test_token_service.py`; `tests/security/test_formal_artifacts.py`; `python -m proofs.run_proverif` | An accepted prototype data token is runtime integrity-protected and bound to the stated fields; the ProVerif implication covers only its abstract tuple. This does not establish a production token-signature scheme beyond the prototype HMAC issuer boundary. |
| T2 DEK secrecy from Provider (symbolic only; concrete toy backend refuted) | `presaga_dek_secrecy.pv`: `query attacker(secret_dek)`; `TransformIssued(...) ==> PolicyAllow(...)` | owner/requester/record/class/purpose/version in symbolic terms; audit booleans only describe code-path instrumentation | `presaga/provider/pre_proxy.py:PREProxy.transform`; `presaga/provider/audit.py:AuditLogger.record`; `presaga/crypto/toy_pre.py`; AES envelope API in `presaga/crypto/envelope.py` | active `experiments/attacks/provider_plaintext_probe.py`; `tests/security/test_attack_scripts.py`; `tests/unit/test_crypto_envelope.py`; accepted release manifest | ProVerif proves its abstract model queries and the service does not explicitly pass plaintext into the transform. The active concrete probe recovers the ToyPRE DEK from public material, so cryptographic Provider confidentiality is not established by this implementation. |
| T3 re-encryption authentication | `presaga_rekey_authentication.pv`: `TransformAccepted(...) ==> TokenIssued(...)`; `TransformRejected(...)` | token requester, record, class, purpose, version, requester-key hash | `presaga/provider/token_service.py:TokenService.validate`; `presaga/provider/pre_proxy.py:PREProxy.transform` | `tests/unit/test_token_service.py`; `tests/integration/test_normal_sharing.py`; `experiments/attacks/requester_mismatch.py`; `experiments/attacks/stale_rekey_use.py` | A transform is attempted only after the data token validates against the present request. The toy key-transform primitive itself is outside this authentication claim. |
| T4 policy denial after contact authorization | `presaga_rekey_authentication.pv`: mismatched `data_token(...)` terms emit `TransformRejected(...)` rather than `TransformAccepted(...)` | `DataSharingPolicy.requester_selector`, `data_scope`, `purposes`, `validity`, `version_constraints`; matching fields in `DataAccessRequest` | `presaga/provider/data_policy.py:DataPolicyEvaluator.evaluate`, `_match`; `presaga/protocol/schemas.py:DataSharingPolicy`, `DataAccessRequest` | `tests/unit/test_data_policy.py`; `experiments/attacks/unauthorized_data_class.py`; `experiments/attacks/purpose_mismatch.py`; `tests/security/test_attack_scripts.py` | A SAGA-compatible contact allow is insufficient for data access: an unauthorized class, requester, record, purpose, or version is denied by PRE-SAGA policy. This does not prevent a legitimate requester from leaking already decrypted plaintext. |
| T5 replay prevention | No standalone replay query; it refines the accepted-use condition by preventing a second `TransformAccepted` after token consumption. | `DataToken.max_uses`, `remaining_uses`, signed token state | `presaga/provider/token_service.py:TokenService.validate`, `consume`; `presaga/provider/pre_proxy.py:PREProxy.transform` | `experiments/attacks/token_reuse.py`; `tests/security/test_attack_scripts.py`; `tests/unit/test_token_service.py` | A one-use data token is rejected on replay after a successful transform. Multi-process atomicity and distributed replay resistance require the persistent Provider deployment path and remain separate engineering work. |
| T6 AID registration binding | Not modeled by the current ProVerif files. | requester registration ID/version/key fingerprint; owner registration provenance | `presaga/provider/registry.py`; `presaga/provider/token_service.py`; `presaga/provider/server.py` | `tests/unit/test_agent_registry.py`; `tests/integration/test_management_data_plane.py` | The runtime fails closed after requester-key replacement/revocation and rejects caller-selected key substitution. This is runtime evidence under prototype management authentication, not a formal claim. |
| T7 owner-key rotation and recovery | Not modeled by the current ProVerif files. | owner registration version, wrap provenance, immutable rotation journal, object revision | `presaga/storage/encrypted_store.py`; `presaga/storage/mongo_encrypted_store.py`; `presaga/crypto/key_rotation.py` | `tests/integration/test_owner_key_rotation.py`; `test_rotation_recovery.py`; `test_mongodb_rotation_cas.py` | Prepare/stage/commit or abort and exact cleanup recover across the tested JSON/Mongo states. No multi-object transaction or production key-management guarantee is claimed. |
| T8 repository CAS and Provider fencing | Not modeled by the current ProVerif files. | aggregate `state_revision`; object revision; recovery-required state | `presaga/provider/repository.py`; `json_repository.py`; `mongo_repository.py`; `server.py` | `tests/unit/test_provider_repository.py`; `tests/integration/test_mongodb_provider_service.py`; Mongo release stage | A stale aggregate writer is detected and fenced in the single-active-Provider prototype. CAS is not leader election or distributed linearizability. |

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

The release runner requires real ProVerif output and checks the expected
`RESULT ... is true` query count, not only process exit status. A standalone
run may still record `tool_unavailable`; that state cannot pass the full
release gate.

## Non-goals retained by this matrix

- Concrete security of `presaga.crypto.toy_pre` or `hpke_kem_stub`.
- Endpoint compromise, post-decryption exfiltration, and Provider metadata privacy.
- Memory safety, side channels, and distributed transaction/locking guarantees.
- Full behavioural equivalence between the symbolic model and every deployment.
- Formal coverage of registration rotation, recovery journals, repository CAS,
  Mongo persistence, or Provider fencing.
