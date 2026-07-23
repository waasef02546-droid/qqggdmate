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

## Current local result

ProVerif 2.05 was installed under the local D-drive tool directory:

```text
D:\Users\New project 1\tools\proverif2.05\proverif.exe
```

The proof runner detected this executable and generated real verifier outputs.
All three local proof runs currently report `passed`:

- `presaga_token_secrecy.pv`
- `presaga_dek_secrecy.pv`
- `presaga_rekey_authentication.pv`

The DEK secrecy model additionally reports:

```text
RESULT not attacker(secret_dek[]) is true.
```

## Remaining limitation

The models are still abstract symbolic models. They support protocol-level
claims about token binding, requester/purpose/record/version matching, and
Provider non-plaintext visibility. They do not prove the concrete security of
the toy PRE backend or cover endpoint compromise after a requester legitimately
decrypts plaintext.
