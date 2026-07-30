# PRE-SAGA submission checklist

## Evidence-consistent now

- [x] Contact authorization and data authorization are separated.
- [x] Published experiments use the authoritative Provider service path.
- [x] Attack, task, performance, formal, SAGA bridge, and Mongo artifacts share
  one manifest and source fingerprint.
- [x] ProVerif output is checked by query result, not only exit code.
- [x] ToyPRE public-material recovery remains an explicit defect fixture and
  no publication-facing path selects it.
- [x] A concrete versioned Umbral backend verifies KFrags/CFrags and blocks the
  active data-plane public-material recovery probe while requester decryption
  succeeds.
- [x] Live-Mongo full regression passes (101/101).
- [x] The authoritative manuscript and historical planning drafts are clearly
  separated.

## Required before submission

- [ ] Obtain independent review of the exact `nucypher-core==0.15.0` dependency
  and adapter; current integration is concrete but not independently audited.
- [ ] Run clean-checkout reproduction on another host and record setup time,
  failures, dependency lock, and artifact comparison.
- [ ] Add fair external baselines; current contact-only/plaintext paths are
  modeled local baselines.
- [ ] Expand repetitions, report distributions/confidence intervals, and
  justify workload sizes.
- [ ] Decide whether to implement live SAGA integration or retain the recorded
  evidence bridge as an explicit limitation.
- [ ] Extend formal coverage or explicitly exclude registration rotation,
  recovery journal, Mongo CAS, and Provider fencing from theorem statements.
- [ ] Complete a primary-source literature review for PRE, HPKE, capability
  security, OAuth/DPoP, multi-agent authorization, and reproducible systems
  evaluation.
- [ ] Produce final architecture/protocol/attack figures from the current
  implementation and verify their labels against the claim matrix.
- [ ] Create a clean Git tag/commit, dependency lock, artifact archive, and
  anonymous reproduction package.
- [ ] Apply the selected venue template, page limit, artifact policy, ethics
  statement, and citation format.

## Submission stop condition

Do not submit while concrete Provider confidentiality is unsupported or while
the only authoritative run records a dirty source tree. Passing prototype
tests and ProVerif abstract models is not a substitute for those conditions.
