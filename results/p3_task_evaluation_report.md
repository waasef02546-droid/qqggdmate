# P3 task-level evaluation report

## Scope

P3 upgrades evaluation from isolated microbenchmarks toward task-level
prototype evaluation. It does not claim production SAGA/AWS performance.
Instead, it produces repeatable artifacts that explain whether PRE-SAGA works
across representative agent tasks and how latency changes under synthetic
agent, policy, and record scaling.

## Implemented artifacts

- `experiments/evaluation/run_p3_evaluation.py`
  - Generates task success summary.
  - Generates denial-reason summary from the attack matrix.
  - Generates task latency breakdown.
  - Generates synthetic agent/policy/record scalability measurements.
- `experiments/tasks/common.py`
  - Adds timing fields for contact authorization, policy evaluation, token
    issuance, PRE transform, and final decrypt.
- `experiments/run_all.py`
  - Runs P3 evaluation together with attacks, task experiments, and performance
    experiments.
- `tests/security/test_p3_evaluation.py`
  - Verifies generated P3 tables/figures and scalability dimensions.

## Output files

- `results/tables/task_summary.csv`
- `results/tables/denial_reason_summary.csv`
- `results/tables/task_latency_breakdown.csv`
- `results/tables/task_scalability.csv`
- `results/figures/task_latency_breakdown.svg`
- `results/figures/task_scalability.svg`

## Acceptance check

The P3 harness covers the four task families used in the prototype:

- schedule meeting
- expense report
- collaborative writing
- cross-agent memory query

It also covers three scalability dimensions:

- agent count
- policy count
- record count

## Boundary statement

The scalability rows are synthetic in-memory measurements. They are useful for
comparing relative behavior inside the prototype, but they are not a substitute
for a distributed Provider deployment, networked agent runtime, database-backed
storage, or AWS-style deployment experiments.
