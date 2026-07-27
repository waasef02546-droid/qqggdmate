# Impact-based retest policy

Use this table after inspecting the test ledger. It is a selection floor, not permission to rerun
unchanged checks without a reason.

| Change class | Minimum focused verification | Full suite? |
|---|---|---|
| Guidance, ADR, prompt, or claim wording only | Repository control checker; link review when claims change | No |
| Isolated policy or token rule | Direct unit tests plus the nearest positive/negative integration path | Usually no |
| Protocol schema, Provider API, or authorization binding | Unit tests for invariants; integration for issuance, denial, consumption, and replay/boundary behavior | Yes if the schema/API is cross-cutting |
| Crypto envelope, transform, key rotation, or encrypted storage | Direct crypto/storage unit tests; tamper/binding negative path; nearest end-to-end path | Yes for interface or format changes |
| Experiment runner or metric computation | Runner-focused test; one representative execution; artifact schema and provenance check | No unless shared runner infrastructure changed |
| Formal model or query | Syntax/runner test; actual verifier output when the tool is available; traceability update | No |
| Large refactor spanning multiple core areas | Area tests during implementation, then full suite and justified experiments | Yes |
| Release/submission gate | Previously defined regression, reproducibility, artifact, and claim audit | Yes |

## Equivalent-run decision

Treat a prior run as equivalent only when all are unchanged:

- work package and verification target;
- relevant implementation and test code;
- configuration, fixtures, dataset, seeds, and dependency behavior;
- operating environment or external service state; and
- command semantics.

If an equivalent successful result exists, reuse it by reference. Rerun only for invalid/flaky
evidence, an explicit release gate, suspected nondeterminism, or a recorded reason tied to risk.

## Ledger entry requirements

Record the work package, exact target and command, relevant code state, configuration/environment,
result, evidence paths, and rerun reason. A failing run remains evidence; do not overwrite it with a
later pass. Add a new entry and link the causal fix.
