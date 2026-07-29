# Repository ownership and canonical layout

- Decision: `project/` is the only authoritative PRE-SAGA engineering tree.
- Established by: `CFG-002`
- Physical migration completed: `2026-07-28`

## Why this layout exists

The repository previously mixed current implementation, old prototypes, generated evidence,
research reviews, local runtime state, and private inputs at the root. The canonical layout now
makes three distinctions explicit:

1. code that defines current PRE-SAGA behavior;
2. evidence and documents that support or limit paper claims; and
3. legacy, local, or provenance-unknown material that must not be mistaken for current code.

No compatibility links are created. A file has one authoritative location so searches, reviews,
and automated agents do not silently select an obsolete copy.

## Canonical paths

| Path | Purpose | Write rule |
|---|---|---|
| `project/presaga/` | Current protocol, Provider, policy, token, crypto, storage, and agent code | Change only inside an accepted engineering work package |
| `project/experiments/` | Baselines, attacks, end-to-end scenarios, evaluation, and performance | Change only for an accepted experiment or implementation package |
| `project/proofs/` | Formal models and proof runners | Keep assumptions synchronized with implementation |
| `project/tests/` | Focused verification of changed behavior | Tests support implementation; they do not replace it |
| `project/configs/` | Active project configuration | Treat changes as behavior-affecting |
| `project/scripts/` | Active reproducibility and environment tooling | Keep deterministic and documented |
| `project/docs/` | Implementation-level engineering evidence | Link to the behavior it describes |
| `project/results/` | Checked-in experimental evidence | Do not overwrite outside an authorized evidence run |
| `paper/` | Drafts, figures, plans, limitations, and submission material | Claims must match code and evidence |
| `docs/` | Workflow, ADRs, reviews, verification ledger, and repository maps | Keep current with every completed work package |
| `saga_reproduction/` | SAGA baseline reproduction and compatibility material | Retained at its current path until a separate migration |
| `archive/legacy-prototype/` | Preserved non-authoritative prototype, schema, and output | Read-only except for archive maintenance |

## Current top-level structure

```text
/
|-- AGENTS.md
|-- .agents/skills/
|-- .codex/
|-- archive/
|   `-- legacy-prototype/
|       |-- configs/
|       |-- prototype/
|       `-- results/
|-- docs/
|   |-- adr/
|   |-- repository/
|   |-- reviews/saga/
|   |-- verification/
|   `-- workflow/
|-- paper/
|-- project/
|   |-- configs/
|   |-- docs/
|   |-- experiments/
|   |-- presaga/
|   |-- proofs/
|   |-- results/
|   |   `-- legacy/stage2/
|   |-- scripts/
|   `-- tests/
`-- saga_reproduction/
```

## Completed migration

| Former path | Current path | Classification |
|---|---|---|
| `prototype/` | `archive/legacy-prototype/prototype/` | Legacy toy implementation |
| `configs/` | `archive/legacy-prototype/configs/` | Legacy schema/design artifact |
| `results/experiment_summary.csv` | `archive/legacy-prototype/results/experiment_summary.csv` | Legacy prototype output |
| `project/result/` | `project/results/legacy/stage2/` | Legacy Stage-2 evidence |
| `comparison_reports/` | `docs/reviews/saga/` | Research review material |

The migration inventory, hashes, reference changes, and rollback procedure are recorded in
`layout-migration-2026-07-28.md` and `archive-manifest.yaml`.

## Deliberately held paths

| Path | Reason it remains |
|---|---|
| `Record/` | Scripts still contain absolute workspace and `Record` paths |
| `results/compare/` | Source and provenance are not yet recorded |
| `runtime/` | Local MongoDB state; never source or paper evidence |
| `tools/` | Local third-party tool cache and machine-specific outputs |
| `tmp/` | Existing temporary extraction is preserved; future content is ignored |
| `local_conversation_management/` | Private reference input; read-only and ignored |

These paths are not implementation entry points. Moving or deleting them requires a new,
explicitly accepted migration with a reference audit and before/after verification.

## Placement rule for new work

- New behavior belongs in the appropriate `project/` package, not at the root.
- New research reviews belong in `docs/reviews/`.
- New repository decisions and verification records belong in `docs/`.
- New paper artifacts belong in `paper/`.
- Generated local state and external binaries stay ignored.
- Legacy artifacts are preserved under `archive/`; they are never imported by current code.
