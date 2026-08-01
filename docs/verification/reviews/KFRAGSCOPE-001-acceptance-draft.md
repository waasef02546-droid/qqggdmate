# KFRAGSCOPE-001 draft acceptance checklist

Status: proposal only; the work package is not authorized and no implementation has begun.

## A. Bounded security property

- [ ] The protected asset is the DEK for a record-version whose KFrag was never issued to the
  attacker/requester.
- [ ] The attacker may retain a valid KFrag for another record-version under the same owner and
  requester and may call raw `nucypher-core` re-encryption directly, bypassing Provider checks.
- [ ] The acceptance property is falsifiable: record A's retained KFrag cannot enable requester
  decryption of record B's capsule; B's correct KFrag still succeeds.
- [ ] Claims say per-record-version delegating-key separation, not native label-bound PRE.
- [ ] Same-record-version KFrag reuse, legitimate plaintext exfiltration, KMS seed compromise,
  side channels, HSM assurance, and legacy cryptographic erasure remain explicit limitations.

## B. Core production mechanism

- [ ] A versioned, canonical, domain-separated label binds owner AID, record ID, data class,
  record version, authority registration generation, derivation key ID/epoch, backend, and suite.
- [ ] Canonical label bytes and digest have fixed test vectors and reject ambiguity/collision-prone
  encodings.
- [ ] The owner/KMS derives the record SecretKey; the seed and derived private key never enter
  Provider APIs, state, logs, errors, audits, or evidence artifacts.
- [ ] An authority-signed public `RecordDelegatingKeyBinding` binds the label, derived public key,
  authority registration, derivation suite/key ID, and schema version.
- [ ] Storage wraps the DEK to the verified derived public key and persists the binding with exact
  record/version provenance.
- [ ] PREProxy resolves the binding from authoritative stored state and validates wrapper, KFrag,
  context, and binding before transformation; caller-supplied labels or keys are not authoritative.
- [ ] Authority registration keys and record delegating keys are distinct concepts throughout the
  crypto, storage, Provider, agent, and custody interfaces.
- [ ] Custody rotation binds source/target authority registrations separately from source/target
  record-derived keys and preserves owner/KMS custody of derivation secrets.

## C. Persistence, migration, and recovery

- [ ] JSON and Mongo schemas persist bindings byte-exactly and revalidate them on restart.
- [ ] Restarted services reject forged, mismatched, stale-registration, or incomplete bindings.
- [ ] Object CAS, journal CAS, stale-writer fencing, abort, cleanup, exact retry, and conflict
  behavior remain correct with split authority/delegating fields.
- [ ] Legacy wrappers without authenticated derived-key provenance fail closed.
- [ ] Migration is explicit and owner/KMS-assisted: unwrap legacy owner wrap, derive and attest the
  record key, fresh-wrap under that key, CAS-stage, verify, and remove the legacy active wrap.
- [ ] In-flight legacy rotations abort or require re-prepare; no silent schema inference occurs.
- [ ] Loss/rotation/backup obligations for the derivation seed and key ID are documented.

## D. Focused behavioral and attack verification

- [ ] Same-label derivation is deterministic across an owner/KMS restart; changes to record,
  version, owner, registration generation, or derivation epoch yield distinct public keys.
- [ ] Two records and two versions complete the normal contact/token/re-encryption/decrypt path.
- [ ] A legacy characterization reproduces the raw retained-KFrag cross-record weakness using the
  old shared delegating key and labels it historical expected behavior.
- [ ] The authoritative attack bypasses PRE-SAGA context checks, applies A's raw KFrag to B's raw
  capsule, and proves B cannot be decrypted under the new construction.
- [ ] Correct B KFrag succeeds under the identical low-level path, excluding a vacuous failure.
- [ ] Unsigned/forged binding, wrong authority, record, version, label, derived key, requester,
  registration generation, context, wrapper, or malformed encoding fail with stable reasons.
- [ ] Every denial occurs before token consumption, object mutation, or rotation commit.
- [ ] Live Mongo restart and competing-writer/CAS paths pass without skips.
- [ ] Provider-visible-state and release leakage scans find no factory seed, derived private key,
  owner source private key, or plaintext DEK.

## E. Evidence and claim gates

- [ ] Focused positive, negative, and boundary checks pass and are recorded once in the ledger.
- [ ] One full regression is justified and passes because storage, crypto, Provider, and custody
  schemas are cross-cutting; equivalent runs are not repeated afterward without a new reason.
- [ ] The release verifier checks the semantics of the direct raw-KFrag attack, not only row counts.
- [ ] ADR 0010 defines the mechanism, canonicalization, trust boundary, migration, compatibility,
  recovery, and residual risks.
- [ ] Protocol, traceability, paper, limitations, and claims C-003/C-006/C-007/C-008 are reconciled;
  any new scope claim has a direct evidence mapping.
- [ ] Formal artifacts are updated only if a formal scope-authentication claim is made; otherwise
  the exclusion is explicit.
- [ ] A clean-input authoritative release and independent verifier pass.
- [ ] An independent acceptance reviewer checks this list and returns ACCEPT with no unmet item.

## F. Completion and handoff

- [ ] The milestone names the exact source commit, release ID, evidence paths, residual risks, and
  migration status.
- [ ] Repository control validation passes and the result is in the ledger.
- [ ] Only the explicit package allowlist is staged; unrelated user drafts and untracked frontend,
  history, or result material remain untouched.
- [ ] The package stops after acceptance. `REQUESTPOP-001` remains a proposal until separately
  authorized.
