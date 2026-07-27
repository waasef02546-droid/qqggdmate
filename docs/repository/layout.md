# Repository ownership and canonical layout

- Work package: `CFG-002`
- Decision date: `2026-07-28`
- Decision: `project/` is the only authoritative PRE-SAGA engineering tree.

## Canonical paths

| Path | Ownership | Rule |
|---|---|---|
| `project/presaga/` | Core implementation | Authoritative protocol, Provider, policy, token, crypto, storage, and agent code |
| `project/experiments/` | Research execution | Authoritative baselines, attacks, tasks, E2E, evaluation, and performance runners |
| `project/proofs/` | Formal evidence | Authoritative formal models and proof runners |
| `project/tests/` | Verification | Tests that falsify changed behavior; not a substitute for implementation |
| `project/configs/` | Active experiment config | Configuration loaded or required by current framework/tests |
| `project/scripts/` | Active project tooling | Environment and reproducibility checks |
| `project/docs/` | Engineering evidence | Implementation-level traceability |
| `project/results/` | Checked-in result evidence | Only formal experiment/evaluation work packages may update it |
| `paper/` | Paper artifacts | Drafts, figures, limitations, and publication plans |
| `docs/` | Repository control/evidence | Workflow state, ADRs, claims matrix, verification ledger, reviews, and repository maps |
| `saga_reproduction/` | Baseline reproduction | SAGA source copies, compatibility changes, and recorded reproduction evidence |

## Non-canonical root paths

| Path | Classification | Current disposition |
|---|---|---|
| `prototype/` | Legacy toy implementation | Preserve; later move with root legacy config and result CSV |
| `configs/` | Legacy schema/design artifact | Preserve separately; it is not equivalent to `project/configs/` |
| `results/experiment_summary.csv` | Legacy prototype output | Preserve with legacy prototype |
| `results/compare/` | Unknown user material | Hold in place until source/provenance is confirmed |
| `project/result/` | Legacy Stage-2 evidence | Candidate for `project/results/legacy/stage2/` |
| `comparison_reports/` | Research review material | Candidate for `docs/reviews/saga/` |
| `Record/` | SAGA reproduction orchestration/evidence | Keep until absolute paths are parameterized, then move under SAGA reproduction |
| `tools/` | Local external-tool cache | Keep ignored; record versions/sources, never commit binaries |
| `runtime/` | Local MongoDB runtime state | Keep ignored; never treat as evidence or source |
| `tmp/` | Temporary generated extraction | Ignored from now on; existing files are not deleted |
| `local_conversation_management/` | Private reference input | Keep ignored and read-only |

## Target layout

```text
/
├─ AGENTS.md
├─ .agents/skills/
├─ .codex/agents/
├─ docs/
│  ├─ workflow/
│  ├─ adr/
│  ├─ verification/
│  └─ repository/
├─ paper/
├─ project/
│  ├─ presaga/
│  ├─ experiments/
│  ├─ proofs/
│  ├─ tests/
│  ├─ configs/
│  ├─ scripts/
│  ├─ docs/
│  └─ results/
├─ saga_reproduction/
└─ archive/
   └─ legacy-prototype/
```

The target intentionally keeps `saga_reproduction/` at its present path. Current bridge code,
environment scripts, and historical documents reference it directly; renaming it requires a
separate migration work package.

## Safe migration order

1. Freeze this ownership table and the hash inventory in `archive-manifest.yaml`.
2. Keep `project/` as the only documented run entry point.
3. Move `comparison_reports/` and `project/result/` only after updating their small reference sets.
4. Move `prototype/`, root `configs/`, and `results/experiment_summary.csv` together so the old
   schema and output remain reproducible.
5. Parameterize absolute workspace paths in `Record/` before moving it.
6. Do not move `saga_reproduction/`, `tools/`, or `runtime/` inside `CFG-002`.

No source directory is deleted or physically moved by this decision. Physical migration requires
an explicit user-approved archive operation with before/after hashes and updated references.
