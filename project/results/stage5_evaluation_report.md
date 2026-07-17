# Stage 5 Evaluation Report

## Scope

Stage 5 requires system evaluation artifacts beyond simple correctness tests.

The current evaluation adds a reproducible performance harness that compares:

- `saga_contact_only`
- `plaintext_token_server`
- `presaga_policy_only`
- `presaga`

The purpose is to show the extra data-layer control and plaintext exposure boundary, not to claim production-grade throughput.

## Run Command

```powershell
cd project
python -m experiments.performance.run_performance
```

or:

```powershell
cd project
python -m experiments.run_all
```

## Generated Files

| Artifact | Path |
|---|---|
| Performance table | `results/tables/performance.csv` |
| Policy scalability table | `results/tables/scalability_policy_rules.csv` |
| Latency comparison figure | `results/figures/latency_breakdown.svg` |
| Policy scalability figure | `results/figures/scalability_policy_rules.svg` |

## Evaluation Dimensions

The current runner evaluates policy rule counts:

```text
10, 100, 1000
```

Each measurement uses 50 iterations.

## Baseline Interpretation

| Baseline | Data-layer control | Provider sees plaintext data | Provider sees plaintext DEK |
|---|---:|---:|---:|
| SAGA contact only | No | No data path modeled | No data path modeled |
| Plaintext token server | Yes | Yes | Yes |
| PRE-SAGA | Yes | No | No |

## Current Boundary

- The benchmark is an in-memory Python prototype.
- The PRE backend is still `toy_pre`.
- The experiment does not yet measure network, database, or full SAGA Provider overhead.
- Larger data object counts and agent counts remain future work.

## Acceptance Status

Stage 5 minimum evaluation scaffolding is satisfied: the project now generates baseline comparison rows, policy scalability rows, and SVG figures.
