# P4 formal verification pipeline report

## Scope

P4 makes the formal-analysis part of PRE-SAGA executable and traceable. The
main contribution is a reproducible proof runner and a stage-linkage report,
not a claim that a new PRE primitive has been cryptographically proven.

## Implemented artifacts

- `proofs/run_proverif.py`
  - Executes all PRE-SAGA `.pv` files when `proverif` is available on PATH.
  - Writes per-proof output files to `results/proofs/`.
  - Writes `results/proofs/proverif_summary.csv`.
  - Writes `results/proofs/proverif_report.md`.
  - Records `tool_unavailable` when ProVerif is missing.
- `proofs/README.md`
  - Links P1, P2, and P3 artifacts to the formal models.
- `tests/security/test_proverif_runner.py`
  - Verifies that the runner creates auditable output even when ProVerif is not
    installed in the local environment.

## Architecture contribution

P4 strengthens the architecture in three ways:

1. It connects token-field binding to the P1 ContactToken/DataToken layering.
2. It connects requester, purpose, record, data-class, and version checks to
   the P2 attack matrix.
3. It connects Provider non-plaintext visibility to the P3 evaluation artifacts.

## Acceptance criterion

P4 is considered complete for the current local environment if:

- all proof files are enumerated by `proofs/run_proverif.py`;
- every proof has a saved output file;
- `proverif_summary.csv` records `passed`, `failed`, or `tool_unavailable`;
- the status is not silently inferred or manually fabricated;
- test coverage verifies the runner output.

## Current limitation

If ProVerif is not installed on PATH, the current status is a reproducible
environment-blocked run. Installing ProVerif and rerunning the same command will
replace `tool_unavailable` outputs with real verifier output.
