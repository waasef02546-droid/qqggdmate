# PRE-SAGA stage traceability matrix

This matrix connects implementation stages to architecture claims and
evaluation evidence. It is intended to prevent the repository from becoming a
set of isolated scripts.

| Stage | Architecture role | Main artifacts | Evidence produced |
|---|---|---|---|
| P0 framework completion | Establishes the runnable prototype skeleton: Provider facade, encrypted store, PRE interface, configs, seed data, tasks, and baselines. | `presaga/provider/app.py`, `presaga/storage/`, `experiments/data/`, `experiments/tasks/`, `experiments/baselines/` | Unit/integration tests and task scripts run end-to-end. |
| P1 SAGA-compatible adapter | Places PRE-SAGA after a SAGA-compatible contact authorization gate instead of using a disconnected access-control assumption. | `presaga/provider/saga_adapter.py`, `ContactToken`, updated Provider contact path | ContactToken issuance/validation tests and tokenized `saga_contact_only` baseline. |
| P2 attack matrix | Tests whether data-layer authorization still blocks abuse after contact is allowed. | `experiments/attacks/`, `results/tables/security_matrix.csv` | 8/8 attack scenarios blocked with recorded denial reasons. |
| P3 task-level evaluation | Shows that the architecture supports representative tasks and records where latency is spent. | `experiments/evaluation/run_p3_evaluation.py`, task latency/scalability outputs | 4/4 task success, denial summaries, latency breakdown, and synthetic agent/policy/record scalability. |
| P4 formal verification pipeline | Connects protocol claims to executable formal-analysis artifacts and records the verifier environment status. | `proofs/*.pv`, `proofs/run_proverif.py`, `results/proofs/` | Per-proof output files and `proverif_summary.csv`; current status is explicit rather than assumed. |
| MongoDB E2E supplement | Adds a persistent single-node Provider/data-store execution path to reduce the gap with SAGA's MongoDB-backed full-chain engineering. | `presaga/provider/mongo_repository.py`, `presaga/storage/mongo_encrypted_store.py`, `experiments/e2e/mongodb_e2e.py` | Alice/Bob normal decrypt succeeds, Mallory data-layer request is denied, Provider plaintext visibility remains false, and registry/policy/token/audit/encrypted-object collections are populated. |

## Cross-stage dependency chain

```text
P0 runnable framework
  -> P1 SAGA-compatible contact authorization
    -> P2 attacks after contact is allowed
      -> P3 task and scalability evidence
        -> P4 formal-analysis traceability
          -> MongoDB-backed E2E persistence
```

## Current evidence boundary

The current repository supports a prototype-level architecture claim:

> PRE-SAGA can be evaluated as a data-sharing layer after SAGA-compatible
> contact authorization, with token-bound PRE transforms, attack-matrix
> evidence, task-level evaluation, auditable formal-analysis artifacts, and a
> MongoDB-backed persistent E2E execution path.

It does not yet support a production deployment claim involving the original
SAGA Provider, real OTK/DH/ACT pipeline, networked agent runtime, database
backend, or AWS deployment.
