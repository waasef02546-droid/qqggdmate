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
- [ ] Custody protocol ADR records canonical fields, signature domain, key source, key-use
  compromise, replay/idempotency, recovery, migration, and trust limitations.

## B. Core implementation

- [ ] Provider HTTP, management, registry, store, and generic backend interfaces contain no
  `source_private_key` rotation input and no Provider-side decrypt-and-rewrap call.
- [ ] Provider exports a deterministic, versioned, non-secret rewrap request derived from live
  authoritative state.
- [ ] Owner/KMS validates source and intended target fields, rewraps locally, and signs a canonical
  artifact using the authoritative source owner key under a dedicated domain.
- [ ] Provider reconstructs the request, verifies its digest/signature against the source
  registration, validates the target Umbral wrapper key/context, then stages with object CAS.
- [ ] Exact artifact replay is idempotent; a different artifact for the same rotation/object
  conflicts.
- [ ] JSON/Mongo journal and object persistence retain only public requests/digests/signatures and
  encrypted wrappers, never keys or plaintext DEKs.
- [ ] Legacy `source_private_key_b64` fails closed with no compatibility fallback.

## C. Verification

- [ ] Positive Umbral prepare → export → owner/KMS → stage → commit → cleanup → target decrypt.
- [ ] Wrong owner key fails in custody before an artifact exists.
- [ ] Forged signature, altered target wrapper, wrong target key/context, cross-record,
  cross-rotation, stale revision, and malformed artifact are denied before mutation.
- [ ] Exact retry after simulated lost response is safe; conflicting retry is rejected.
- [ ] Partial multi-object staging blocks commit; abort/cleanup preserves source wraps.
- [ ] Token issued before owner rotation is denied after commit without consumption.
- [ ] Provider service state, journal, audit, exception text, and generated evidence pass a
  raw/base64/hex source-key and DEK leakage scan.
- [ ] JSON restart before stage and after stage remains recoverable.
- [ ] Live Mongo object/journal CAS, restart recovery, duplicate receipt, and stale-writer tests
  pass without skips.
- [ ] One impact-justified full regression passes after all focused checks.

## D. Experiment, claims, and reproducibility

- [ ] Release adds a semantic key-custody gate rather than relying only on test counts.
- [ ] Claims C-003/C-006/C-007/C-008, traceability, protocol, ADR, and paper agree with code.
- [ ] Limitations explicitly retain co-located-process, KFrag-copy, KMS-memory, static-Bearer,
  non-transactional multi-object, and upstream Alpha/GPL boundaries.
- [ ] ProVerif is not rerun unless a modeled event/query changes; current models remain explicitly
  out of scope for rotation/custody.
- [ ] Ledger records commands, environment, code state, failures, causal reruns, and evidence.
- [ ] Clean source commit, authoritative release, artifact hashes, independent verifier, and
  independent final audit all pass.

## E. Closure

- [ ] Every applicable item above is checked with evidence links.
- [ ] Current milestone and residual risks are updated.
- [ ] No unrelated user files are staged.
- [ ] Final implementation/evidence commit exists; push uses a normal branch update, never force.
- [ ] `KFRAGSCOPE-001` remains unstarted pending separate authorization.
