# KEYCUSTODY-001 acceptance checklist

- Work package: `KEYCUSTODY-001`
- State: `implementation-and-verification`
- Decision: `pending`
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
- [x] JSON/Mongo journal and object persistence retain only public requests/digests/signatures and
  encrypted wrappers, never keys or plaintext DEKs.
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
- [ ] Clean source commit, authoritative release, artifact hashes, independent verifier, and
  independent final audit all pass. Source commit, release, hashes, and verifier pass; final audit
  is in progress.

## E. Closure

- [ ] Every applicable item above is checked with evidence links.
- [ ] Current milestone and residual risks are updated.
- [ ] No unrelated user files are staged.
- [ ] Final implementation/evidence commit exists; push uses a normal branch update, never force.
- [ ] `KFRAGSCOPE-001` remains unstarted pending separate authorization.
