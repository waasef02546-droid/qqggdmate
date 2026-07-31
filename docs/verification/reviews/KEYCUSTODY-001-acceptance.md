# KEYCUSTODY-001 acceptance checklist

- Work package: `KEYCUSTODY-001`
- State: `accepted-local / remote-push-pending`
- Decision: `ACCEPT`
- Reviewer rule: a checked item requires an implementation path and repeatable evidence; prose or
  a test without authoritative core behavior is insufficient.

## A. Scope and design

- [x] Objective is one falsifiable behavior: Provider rotation receives no source private key or
  plaintext DEK and stages only an authenticated, exactly bound custody artifact.
- [x] Protected assets, attacker/error model, failure behavior, non-goals, and affected core paths
  are explicit in the current milestone.
- [x] KFrag scope is separated: per-record-version keys are selected for a later package;
  label-bound PRE is not claimed.
- [x] Custody protocol ADR records canonical fields, signature domain, key source, key-use
  compromise, replay/idempotency, recovery, migration, and trust limitations.

## B. Core implementation

- [x] Provider HTTP, management, registry, store, and generic backend interfaces contain no
  `source_private_key` rotation input and no Provider-side decrypt-and-rewrap call.
- [x] Provider exports a deterministic, versioned, non-secret rewrap request derived from live
  authoritative state.
- [x] Owner/KMS requires an exact owner-local approval for rotation, record, revision, source and
  target fields; target substitution is denied before local rewrap/signing.
- [x] Provider reconstructs the request, verifies its digest/signature against the source
  registration, validates the target Umbral wrapper key/context, then stages with object CAS.
- [x] Exact artifact replay is idempotent; a different artifact for the same rotation/object
  conflicts.
- [x] JSON/Mongo object state persists only encrypted wrappers plus public digest/provenance;
  custody signatures are verified before staging and are not persisted as restart attestations.
- [x] Legacy `source_private_key_b64` fails closed with no compatibility fallback.

## C. Verification

- [x] Positive Umbral prepare → export → owner/KMS → stage → commit → cleanup → target decrypt.
- [x] Wrong owner key fails in custody before an artifact exists.
- [x] Forged signature, altered target wrapper, wrong target key/context, cross-record,
  cross-rotation, stale revision, and malformed artifact are denied before mutation.
- [x] Exact retry after simulated lost response is safe; conflicting retry is rejected.
- [x] Partial multi-object staging blocks commit; abort/cleanup preserves source wraps.
- [x] Token issued before owner rotation is denied after commit without consumption.
- [x] Provider service state, journal, audit, exception text, and generated evidence pass a
  raw/base64/hex source-key and DEK leakage scan.
- [x] JSON restart before stage and after stage remains recoverable.
- [x] Live Mongo object/journal CAS, restart recovery, duplicate receipt, and stale-writer tests
  pass without skips.
- [x] One impact-justified full regression passes after all focused checks.

## D. Experiment, claims, and reproducibility

- [x] Release adds a semantic key-custody gate rather than relying only on test counts.
- [x] Claims C-003/C-006/C-007/C-008, traceability, protocol, ADR, and paper agree with code.
- [x] Limitations explicitly retain trusted local-approval input, KFrag-copy, KMS-memory,
  static-Bearer, non-transactional multi-object, trusted-repository recovery, and upstream
  Alpha/GPL boundaries.
- [x] ProVerif is rerun only because the authoritative full-release gate requires it; no new
  rotation/custody formal claim is made and current models remain explicitly out of scope.
- [x] Ledger records commands, environment, code state, failures, causal reruns, and evidence.
- [x] Clean source commit, authoritative release, artifact hashes, independent verifier, and
  independent final audit all pass.

## Accepted evidence

- Final source commit: `5f1cea694249397095672867d087daab4630be36`.
- Authoritative release: `20260731T111704Z-c1d0f804`.
- Source fingerprint: `b63f2e09a6503346f7e62b4e9fe82ce27afa5b0c6651f727b225ee86a5fb2595` over 145 files.
- Release result: 10/10 gates, 24 artifacts, `release_inputs_dirty=false`, independent verifier PASS.
- Verification: 26/26 approval/custody/Mongo/release checks and 117/117 full regression with live
  Mongo and no skips.
- Independent reviewer decision: `ACCEPT`; no unmet items. Residual risks are the trusted local
  approval file, trusted repository on restart, owner/KMS key and DEK memory, static Bearer
  management authentication, key-pair-scoped KFrags, non-transactional multi-object rotation, and
  the Alpha/GPL prototype dependency.

## E. Closure

- [x] Every applicable item above is checked with evidence links.
- [x] Current milestone and residual risks are updated.
- [x] No unrelated user files are staged.
- [ ] Final implementation/evidence commit `ef0c814` exists; normal push is pending explicit
  authorization for uploading this branch to the configured GitHub remote. No force push or
  workaround was attempted.
- [x] `KFRAGSCOPE-001` remains unstarted pending separate authorization.
