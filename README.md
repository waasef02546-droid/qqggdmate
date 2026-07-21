# PRE-SAGA Prototype

This directory contains the PRE-SAGA prototype implementation.

The prototype implements a SAGA-compatible contact authorization layer followed
by PRE-SAGA data sharing:

- SAGA-compatible contact token adapter
- Data Sharing Policy evaluator
- data token service
- encrypted store
- toy PRE interface
- attack matrix
- task-level evaluation
- formal-analysis runner

The cryptographic backend is intentionally marked as `toy_pre`. It is used to validate protocol behavior and test bindings, not for production security.

## Run tests

```powershell
cd project
python -m unittest discover -s tests -v
```

## Expected result

All tests should pass. The tests cover:

- SAGA-compatible contact token issuance and validation
- allowed data sharing
- data class denial
- purpose mismatch
- requester mismatch
- data version mismatch
- token max-use exhaustion
- encrypted store round trip
- PRE transform without Provider plaintext DEK exposure
- task-level evaluation artifact generation
- ProVerif runner output tracking

## Run all experiments

```powershell
cd project
python -m experiments.run_all
```

The combined runner generates or refreshes:

```text
results/tables/security_matrix.csv
results/tables/task_results.csv
results/tables/task_summary.csv
results/tables/denial_reason_summary.csv
results/tables/task_latency_breakdown.csv
results/tables/task_scalability.csv
results/proofs/proverif_summary.csv
```

The attack scripts intentionally run after a SAGA-compatible contact gate allows
the requester. This shows that PRE-SAGA blocks data-layer abuse even when
contact is permitted.

## Run formal-analysis artifacts

```powershell
cd project
python -m proofs.run_proverif
```

If ProVerif is installed and on PATH, the runner saves real verifier output
under `results/proofs/`. If it is not installed, the runner records
`tool_unavailable` so the verification status remains auditable.
