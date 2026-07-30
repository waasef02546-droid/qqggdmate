# Current milestone

## Active work package

- ID: `CRYPTO-001`
- Title: Concrete Umbral PRE backend and malicious-Provider recovery gate
- State: `accepted`
- Authorization date: `2026-07-31`
- Acceptance date: `2026-07-31`
- Objective: replace publication-facing ToyPRE/HPKE stubs with a concrete Umbral proxy
  re-encryption adapter, preserve the existing server-enforced authorization chain, and require
  the data-plane Provider recovery probe to fail while the intended requester still decrypts.
- Primary implementation paths:
  - `project/presaga/crypto/`
  - `project/presaga/provider/`
  - `project/experiments/`
  - `project/tests/`
  - `project/proofs/`
  - `project/docs/traceability_matrix.md`
  - `docs/claims-evidence-matrix.md`
  - `paper/`
- Construction decision: use the Umbral primitives exposed by `nucypher-core==0.15.0`
  (`MessageKit`, signed/verified key fragments, capsule re-encryption, and verified capsule
  fragments). Do not relabel an owner-mediated X25519/AEAD key-sharing composition as PRE.
- Trust boundary: the malicious-Provider recovery gate covers the data-token and re-encryption
  data plane. Owner key generation and rekey generation remain owner-side. Existing key rotation
  runs through the separately trusted management plane and may materialize a DEK inside that
  trusted process boundary; this package does not establish HSM/KMS isolation.
- Non-goals:
  - claiming production security, independent cryptographic audit, side-channel resistance,
    secure-memory zeroization, HSM/KMS custody, or upstream maintenance guarantees;
  - silently migrating existing ToyPRE/HPKE ciphertexts;
  - proving the Rust implementation equivalent to the ProVerif abstraction;
  - changing Contact/data-policy semantics or distributed Provider behavior.

## Selected orchestration mode

- Mode: primary-agent integration with three bounded parallel read-only audits.
- The primary agent owns construction choice, production edits, integration, verification
  selection, claims, and release evidence.
- Audits cover backend/dependency suitability, call-graph migration, and independent evidence and
  claim review. No overlapping writes are permitted.

## Acceptance criteria

- A versioned `UmbralPREBackend` performs owner wrap, signed 1-of-1 rekey generation, proxy
  transform, original-owner decrypt, and intended-requester decrypt using
  `nucypher-core==0.15.0`.
- Ciphertext, rekey, and transformed packages are fail-closed and bind the owner key, requester
  key, and exact owner-wrap context; wrong keys, wrong context, truncation, substitution, and
  tampering return no plaintext.
- The Provider transform verifies the expected requester and stored-object context before
  returning transformed material. Cryptographic failures are denied and audited without leaking
  plaintext or an uncaught implementation exception.
- The HTTP service default and every authoritative publication experiment use
  `UmbralPREBackend`; ToyPRE and HPKE stubs remain only as explicitly labelled defect/protocol
  fixtures.
- The malicious-Provider regression snapshots the Provider-visible owner wrap, public keys,
  context, rekey, transformed material, registrations, policies, tokens, encrypted objects, and
  complete audit metadata; it finds no raw/base64/hex DEK, rejects direct public-key unwrap misuse,
  and the registered requester succeeds. It is not cryptanalysis or a whole-process proof.
- The historical ToyPRE public-material recovery stays covered by a focused regression, but is no
  longer accepted as the active release backend.
- Trusted-management-plane rotation still succeeds with the concrete backend and is described as
  trusted decrypt-and-rewrap, not proxy transformation.
- Focused positive, negative, boundary, service, rotation, attack, and release-schema checks pass.
  One full regression and a fresh authoritative release are required because the backend,
  ciphertext format, service default, experiments, and evidence schema are cross-cutting.

## Evidence obligations

- Record the construction, package formats, key custody, upstream version/license/maintenance
  limits, migration behavior, and threat boundary in ADR 0008.
- Invert the active Provider recovery release gate from expected ToyPRE compromise to expected
  concrete-backend resistance, and keep requester usability in the same probe.
- Update traceability and claims so concrete evidence is `prototype-bounded`, not production
  cryptographic assurance.
- Keep the ProVerif result explicitly abstract; change and rerun it only if the modeled protocol
  events or queries change.
- Record every verification command, result, code state, environment, and rerun reason in the
  test ledger.
- Produce a fresh manifest from a clean release-input commit and independently verify it before
  acceptance.

## Risks

- `nucypher-core` is an alpha Python binding to a Rust implementation and is GPLv3; dependency and
  redistribution implications must remain visible.
- Upstream `pyUmbral` is inactive. The selected package exposes working Umbral primitives but this
  repository has not independently audited their implementation.
- Versioned Umbral packages are incompatible with legacy ToyPRE/HPKE wraps. Unknown or legacy
  formats must fail closed; migration requires an explicitly trusted unwrap-and-rewrap operation.
- The management and data planes are logically separated but can be deployed in one process.
  Compromise of a co-located trusted management plane is outside the data-plane confidentiality
  claim.
- The worktree contains unrelated user and historical files. Only CRYPTO-001 release inputs may be
  staged or committed.

## Verification evidence

- Local API compatibility smoke on Python 3.12:
  `NUCYPHER_CORE_UMBRAL_SMOKE: PASS` for MessageKit owner decrypt, signed key-fragment
  serialization/verification, capsule re-encryption, capsule-fragment verification, and requester
  decrypt.
- Backend unit verification: 9/9 passed for owner/requester round trips, exposed-public-material
  regression, authoritative-owner/requester/context mismatch, malformed and tampered
  envelopes/KFrag/CFrag, wrong private keys, explicit DEK size, and trusted-management rewrap.
- Focused Provider, storage, registration, rotation, attack, task, performance, bridge,
  traceability, and release-verifier checks passed after two evidenced compatibility corrections:
  algorithm-domain fingerprinting of rotation candidates and the expected HTTP algorithm label.
- Invalid Umbral crypto material is denied and audited without consuming the token; a subsequent
  valid transform with the same one-use token succeeds.
- Live MongoDB 8.3.4 focused verification: 5/5 passed with no skips against an isolated database
  on `127.0.0.1:27018`.
- Full live-Mongo regression: 101/101 passed with no skips.
- Release preflight staging `20260730T190452Z-b76cb299` passed all eight scientific/evidence
  gates: 8/8 blocking attacks (including the concrete recovery probe), 0 active toy limitation
  paths, 4/4 tasks, 12/12 performance rows, 3/3 ProVerif models/four true queries, 2/2 SAGA bridge
  cases, and live Mongo E2E. It was correctly rejected only by `release_inputs_clean` before the
  deliberate source commit.
- Initial release-input commits:
  `9d4b99812b971f04e4fa0baf8790e999d3fd1557` (implementation) and
  `567e79af7c5b2b86016d9e7c3e2ad2d975a02e3e` (non-self-referential final claims), followed by
  `99c3b1bdde487c03a14188447e7d0b3235144542` (paper/manifest fact alignment).
- Final independent audit then required direct wrapper-owner-key comparison with the active owner
  registration, an exposed-state/public-API probe boundary, non-consuming crypto failure ordering
  in the protocol specification, removal of an unimplemented request-signature claim, and a
  performance-to-security-gate linkage field. These corrections are committed at
  `7c27e7ce8f01922dd5c75190fcdb2d1c57e391c7`; the final evidence wording is committed at
  `95061e6c1f8d9f04d182475dc365bb8b24575a36`.
- Post-audit focused verification passed 40/40 tests, including malicious stored-wrapper
  substitution with unchanged provenance; the denial was audited and did not consume the token.
  One release-schema test also passed after the final wording-only adjustment.
- Accepted authoritative run: `20260730T193022Z-41303f6f`.
- Source fingerprint:
  `0fd338a39d5ec2ec6ee4ecd376309412f5c13cfc0e434c0b88bd790a3001316e`
  across 138 declared source files.
- All nine release gates passed and the independent verifier accepted all 23 artifacts.
- Acceptance review: `docs/verification/reviews/CRYPTO-001-acceptance.md`.

## Previous accepted work packages

- `REL-001`: accepted on `2026-07-29`; authoritative experiment provenance, release manifest,
  independent verifier, real ProVerif, live Mongo, and honest ToyPRE limitation evidence.
- `CORE-005`: accepted on `2026-07-29`; revisioned JSON/Mongo repository contract, restart recovery,
  service-driven Mongo E2E, and stale-writer fencing.
- `FE-001`: accepted on `2026-07-29`; local demonstration console and loopback Provider proxy.
- `CORE-004`: accepted on `2026-07-29`; persistent rotation history, restart recovery, terminal
  cleanup, and live Mongo per-document CAS.
- `CORE-003`: accepted on `2026-07-28`; registration-bound owner-wrap provenance and authenticated
  prepare/rewrap/commit-or-abort lifecycle.
- `CORE-002`: accepted on `2026-07-28`; authenticated AID-to-key binding, versioned registry, and
  management/data-plane separation.
- `CFG-002`: accepted on `2026-07-28`; repository normalization and canonical engineering layout.
- `CORE-001`: accepted on `2026-07-26`; server-enforced Contact-to-data-token-to-re-encryption
  binding.

## Proposed next work package

- Candidate ID: `KEYCUSTODY-001`
- Candidate topic: move rotation decrypt-and-fresh-encrypt to an owner/KMS boundary and decide
  between per-record delegating keys and a label-bound PRE construction for retained-KFrag scope.
- State: `awaiting_user_choice`
- Rule: do not begin this candidate automatically.
