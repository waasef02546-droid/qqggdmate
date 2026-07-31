# PRE-SAGA Proof--Code--Experiment Traceability Matrix

## Purpose and reading rule

This matrix binds each paper-level security claim to (1) a symbolic-model event
or query, (2) the prototype schema and enforcing code path, and (3) a
repeatable test or experiment. It is evidence of *prototype conformance to
the stated model boundary*, not a proof that the selected concrete dependency
or adapter is production-secure.

The authoritative formal files are under `proofs/`.  Code references below are
repository-relative to `project/`; test and experiment commands are run from
the `project/` directory.

## Matrix

| ID | Formal event / query | Bound protocol fields | Enforcing implementation | Repeatable evidence | Paper claim and boundary |
|---|---|---|---|---|---|
| T1 data-token authenticity | `presaga_token_secrecy.pv`: `DataTokenAccepted(...) ==> DataTokenIssued(...)` | The symbolic model carries owner/requester/record/class/purpose/version. Runtime signing additionally covers `allowed_record_ids`, `allowed_data_classes`, `min_version`, `max_version`, `requester_public_key_hash`, registration fields, and `issuer_signature`. | `presaga/protocol/schemas.py:DataToken`; `presaga/provider/token_service.py:TokenService.issue_data_token`, `validate`, `_sign` | `tests/unit/test_token_service.py`; `tests/security/test_formal_artifacts.py`; `python -m proofs.run_proverif` | An accepted prototype data token is runtime integrity-protected and bound to the stated fields; the ProVerif implication covers only its abstract tuple. This does not establish a production token-signature scheme beyond the prototype HMAC issuer boundary. |
| T2 DEK secrecy from the data-plane Provider | `presaga_dek_secrecy.pv`: `query attacker(secret_dek)`; `TransformIssued(...) ==> PolicyAllow(...)` | The symbolic model carries owner/requester/record/class/purpose/version. The adapter additionally binds the exact owner-wrap context digest, authoritative owner Umbral public key, requester Umbral public key, suite, version, and artifact kind. | `presaga/provider/pre_proxy.py:PREProxy.transform`; `presaga/crypto/umbral_pre.py`; audit and encrypted stores; AES envelope API | active `experiments/attacks/provider_plaintext_probe.py`; `tests/unit/test_umbral_pre.py`; `tests/security/test_attack_scripts.py`; authoritative release | ProVerif proves only its idealized queries. The concrete regression snapshots Provider-exposed state and Umbral artifacts, finds no raw/base64/hex DEK, rejects direct public-key use of the unwrap API, and separately requires requester decryption to succeed. This is prototype-bounded exposed-state evidence, not cryptanalysis; trusted-management compromise, Provider/requester collusion, memory/side channels, and implementation equivalence are not proved. |
| T3 re-encryption authentication | `presaga_rekey_authentication.pv`: `TransformAccepted(...) ==> TokenIssued(...)`; `TransformRejected(...)` | token requester, record, class, purpose, version, requester-key hash; concrete authoritative owner/requester keys and owner-wrap context | `presaga/provider/token_service.py:TokenService.validate`; `presaga/provider/pre_proxy.py:PREProxy.transform`; `presaga/crypto/umbral_pre.py:UmbralPREBackend.transform` | token tests; Umbral KFrag/CFrag tamper, registration-key substitution, wrong-key, and wrong-context tests; normal-sharing and attack experiments | The Provider validates request/token/registration state, compares the wrapper owner key with the active owner registration, verifies the signed KFrag against that key and the live requester key, and only then consumes a one-use token. Invalid crypto artifacts are denied and audited without token consumption. KFrag scope remains key-pair-wide rather than purpose- or token-specific. |
| T4 policy denial after contact authorization | `presaga_rekey_authentication.pv`: mismatched `data_token(...)` terms emit `TransformRejected(...)` rather than `TransformAccepted(...)` | `DataSharingPolicy.requester_selector`, `data_scope`, `purposes`, `validity`, `version_constraints`; matching fields in `DataAccessRequest` | `presaga/provider/data_policy.py:DataPolicyEvaluator.evaluate`, `_match`; `presaga/protocol/schemas.py:DataSharingPolicy`, `DataAccessRequest` | `tests/unit/test_data_policy.py`; `experiments/attacks/unauthorized_data_class.py`; `experiments/attacks/purpose_mismatch.py`; `tests/security/test_attack_scripts.py` | A SAGA-compatible contact allow is insufficient for data access: an unauthorized class, requester, record, purpose, or version is denied by PRE-SAGA policy. This does not prevent a legitimate requester from leaking already decrypted plaintext. |
| T5 replay prevention | No standalone replay query; it refines the accepted-use condition by preventing a second `TransformAccepted` after token consumption. | `DataToken.max_uses`, `remaining_uses`, signed token state | `presaga/provider/token_service.py:TokenService.validate`, `consume`; `presaga/provider/pre_proxy.py:PREProxy.transform` | `experiments/attacks/token_reuse.py`; `tests/security/test_attack_scripts.py`; `tests/unit/test_token_service.py` | A one-use data token is rejected on replay after a successful transform. Multi-process atomicity and distributed replay resistance require the persistent Provider deployment path and remain separate engineering work. |
| T6 AID registration binding | Not modeled by the current ProVerif files. | requester registration ID/version/key fingerprint; owner registration provenance | `presaga/provider/registry.py`; `presaga/provider/token_service.py`; `presaga/provider/server.py` | `tests/unit/test_agent_registry.py`; `tests/integration/test_management_data_plane.py` | The runtime fails closed after requester-key replacement/revocation and rejects caller-selected key substitution. This is runtime evidence under prototype management authentication, not a formal claim. |
| T7 owner-key rotation, custody, and recovery | Not modeled by the current ProVerif files. | owner registration version, wrap provenance, immutable rotation journal, object revision, canonical custody request digest, authenticated target wrapper | `presaga/crypto/key_custody.py`; `presaga/storage/encrypted_store.py`; `presaga/storage/mongo_encrypted_store.py`; `presaga/provider/registry.py`; `presaga/provider/server.py` | `tests/unit/test_key_custody.py`; `tests/security/test_key_custody_boundary.py`; `tests/integration/test_owner_key_rotation.py`; `test_rotation_recovery.py`; live `test_mongodb_rotation_cas.py` and `test_mongodb_provider_service.py`; semantic release custody gate | Prepare/export/owner-custody/stage/commit or abort and exact cleanup recover across the tested JSON/Mongo states. Provider interfaces reject source private keys; exact artifact retry is idempotent and tampered/cross-object/conflicting artifacts fail before mutation. The owner/KMS still handles the source key and DEK; no HSM, multi-object transaction, or production key-management guarantee is claimed. |
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

- Production security or independent audit of `nucypher-core`, the adapter,
  `toy_pre`, or `hpke_kem_stub`.
- Provider/requester collusion with retained key-pair-scoped KFrags, or
  compromise of the owner/KMS custody process.
- Endpoint compromise, post-decryption exfiltration, and Provider metadata privacy.
- Memory safety, side channels, and distributed transaction/locking guarantees.
- Full behavioural equivalence between the symbolic model and every deployment.
- Formal coverage of registration rotation, recovery journals, repository CAS,
  Mongo persistence, or Provider fencing.
