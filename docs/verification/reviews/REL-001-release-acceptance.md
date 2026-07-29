# REL-001 acceptance review

- Work package: `REL-001`
- Review date: 2026-07-29
- Outcome: accepted as a paper-evidence control plane for the bounded prototype
- Authoritative run: `20260729T123951Z-23c9fbf1`
- Release-input commit:
  `6109b3eb6318a9714ee29b65da2340be5a6abcdf`

## What changed

REL-001 moved publication-facing attacks, tasks, scalability, full-service
performance, SAGA bridge, and Mongo E2E onto the `ProviderService` facade.
Data-token issuance now owns one allow/deny audit event in the Provider domain
and returns its audit ID; the HTTP service persists it without adding a
duplicate.

The combined runner now stages evidence, applies semantic gates, records source,
configuration, environment, tool, and artifact hashes, invokes an independent
verifier, and publishes only an accepted set. Tests write to temporary output
paths instead of the canonical result directory.

## Acceptance criteria

| Criterion | Result | Evidence |
|---|---:|---|
| One domain issuance audit for allow and policy deny | pass | contact-binding and HTTP integration tests |
| Publication attacks use the authoritative service decision | pass | 7/7 expected-blocked rows have `path_kind=provider_service` |
| Full PRE-SAGA flow does not double-evaluate policy | pass | shared Provider harness and performance/scalability code review |
| Staged, gated, manifest-controlled publication | pass | accepted release manifest |
| Independent verifier accepts current evidence | pass | `RELEASE_VERIFY: PASS` |
| Verifier rejects modification | pass | release evidence tamper test |
| Verifier rejects path/gate/artifact/paper-source drift | pass | hardened semantic and source checks |
| Release inputs are clean and reconstructible | pass | Git commit `6109b3e`; clean-input gate |
| Real formal and persistence dependencies | pass | ProVerif 2.05; MongoDB 8.3.4 |
| Focused regression | pass | 22/22 |
| Full cross-cutting regression | pass | 89/89 with live Mongo |
| Paper wording matches implementation | pass | claim matrix, traceability matrix, and authoritative manuscript |

## Security-claim correction

The most important review result is negative: ToyPRE masks a DEK using material
derivable from the owner public key and context. The active probe recovers the
same DEK. Therefore:

- the service has a structural non-materialization property;
- the abstract ProVerif DEK query succeeds within its model;
- the concrete prototype does not establish Provider-side DEK confidentiality.

Claim `C-003` is intentionally `partial`. Any wording that says the current
Provider “cannot obtain the DEK” is rejected.

## Release evidence

- 7/7 expected-blocked attacks
- 1/1 active ToyPRE limitation probe
- 4/4 task scenarios
- 12/12 configured performance rows
- 9/9 task scalability rows with success rate 1.0
- 3/3 ProVerif models and 4 verified true queries
- 2/2 SAGA bridge cases
- Mongo normal path and data-policy attack path passed
- 89/89 repository tests passed with live Mongo

The manifest captures 23 authoritative artifacts and 132 release-input files.
Those inputs were clean at commit
`6109b3eb6318a9714ee29b65da2340be5a6abcdf`; unrelated workspace materials
were still present and are recorded separately. The manifest is not signed or
externally witnessed, so its guarantee is manifest-relative integrity rather
than malicious publisher authenticity.

## Independent audit synthesis

Three bounded read-only audits examined experiment provenance, paper claims,
and clean-environment reproducibility. Their material findings were addressed:

- direct policy evaluation and manual audit synthesis were removed from
  publication paths;
- cross-run task latency consistency is checked;
- the verifier rejects non-Provider attack paths, missing gates, incomplete
  artifact inventories, and authoritative-paper/claim drift;
- ProVerif query text, SAGA evidence paths, Mongo database safety, dependency
  declarations, and test-output isolation are enforced;
- stale and overbroad paper statements are no longer authoritative;
- release limitations name the missing real crypto, live SAGA, distributed
  Mongo, and broader SAGA-style evaluations.

## Residual risks and next candidate

REL-001 is complete, but the project is not publication-ready. The highest
priority candidate is `CRYPTO-001`: replace ToyPRE with a reviewed concrete
backend, define an adversarial provider-confidentiality acceptance test, and
rerun the active recovery probe. Comparative baselines, clean-host
reproduction, and venue-ready literature/formatting should follow that
cryptographic correction rather than precede it.
