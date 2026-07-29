# ADR 0007: Make one staged Provider path authoritative for release evidence

- Status: Accepted
- Date: 2026-07-29
- Work package: `REL-001`
- Claim mapping: upgrades `C-002` and `C-004`; narrows `C-003`

## Context

Earlier experiment scripts could call the policy evaluator directly, append
audit events manually, evaluate a request twice, or write into the canonical
`results` directory during tests. Tables from different runs could therefore
look current while describing different source states. ProVerif success was
also inferred from process exit status, and output paths embedded local
absolute directories.

The audit additionally found a security-claim defect: ToyPRE derives its mask
from public material. A Provider that has the owner-wrapped DEK, owner public
key, and context can reverse that mask. The existing audit booleans showed
only that the transform function did not explicitly receive plaintext; they
did not establish cryptographic inability to recover it.

## Decision

### Authoritative service path

- Data-token issuance records exactly one allow/deny
  `data_token_issuance` event in `PREProviderApp`.
- `ProviderService` persists that domain event and does not synthesize a
  second denial audit.
- Attacks, tasks, scalability, performance full flows, and the SAGA bridge use
  `AuthoritativeProviderHarness`, which crosses `ProviderService`.
- Microbenchmarks remain explicitly labeled as modeled or policy-only paths.

### Active limitation evidence

`provider_plaintext_probe` actively tries public-material DEK recovery. Its
expected result is that recovery succeeds against ToyPRE. A release fails if
this probe is silently converted back into a false “blocked” confidentiality
claim. Structural non-materialization and concrete cryptographic
confidentiality are recorded as different properties.

### Staged release

`python -m experiments.run_all --mongo-uri <uri>`:

1. writes all artifacts into a unique staging directory;
2. requires attack, task, performance, ProVerif, SAGA bridge, and live-Mongo
   gates;
3. records source/config/tool/artifact hashes and environment versions;
4. invokes an independent semantic and integrity verifier;
5. publishes each accepted file by temporary replacement, with the manifest
   written last. A mid-publication interruption is detectable, but the whole
   directory is not one atomic transaction.

Tests use temporary output paths. Mongo release databases require the
`presaga_release_` prefix and must be empty; the runner never resets an
existing database.

## Consequences

- `project/results/release-manifest.json` is the authority for the current
  release. Unlisted files are historical or auxiliary.
- Cross-run task latency mismatches, modified or incomplete artifact sets,
  missing/failed gates, non-Provider attack paths, absolute SAGA evidence
  paths, and source or authoritative-paper drift make verification fail.
- ProVerif output must contain the expected true-query count; exit code alone
  is insufficient.
- A dirty Git state is permitted only when explicitly recorded and
  fingerprinted. A clean commit remains preferable for external reproduction.

## Evidence

- Accepted run: `20260729T121720Z-e77ba61e`
- Independent verifier: pass
- Gates: 7/7 blocking attacks, one active limitation probe, 4/4 tasks, 12
  performance rows, three ProVerif models/four verified queries, two SAGA
  bridge cases, and live Mongo E2E
- Full regression: 89/89 tests passed with MongoDB 8.3.4

## Boundaries

This decision does not turn ToyPRE/HPKE stubs into production cryptography,
make the ProVerif model equivalent to Python, run a live SAGA network, or
establish distributed Mongo transactions, RAFT, sharding, or multi-Provider
linearizability.
