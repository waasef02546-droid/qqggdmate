# Git baseline report

- Work package: `CFG-002`
- Captured: `2026-07-28`
- Branch: `project`
- HEAD before CFG-002 baseline work: `76d4213dfbf419a472c3a8bc67f758166f96bb67`
- Accepted CORE-001 baseline commit: `9966baba2d37356771d06ae3bee07d50e40f11ae`
- Baseline type: separated commits for known work plus a reviewable residual-worktree
  classification

## Why the repository is not committed automatically

The worktree already contained substantial tracked modifications and untracked user material before
`CFG-002`. A single automatic commit would mix repository control files, accepted `CORE-001`
implementation, paper edits, generated results, historical reproduction material, and unknown PNG
files. Staging or committing all of it would destroy provenance rather than establish one.

No user paper, result, reproduction, or unknown material is reset, stashed, deleted, moved, staged,
committed, or pushed by `CFG-002`. The already accepted CORE-001 implementation was committed
separately as:

These preserved files are **not a commit candidate for CFG-002**. They remain visible in the
worktree so that a later, explicitly authorized paper, evidence, or archive work package can review
their provenance before acting.

```text
9966bab feat(auth): bind contact sessions to data-token consumption
```

## Snapshot

Before separating the CORE-001 implementation:

- tracked modified files: 40;
- untracked non-ignored files: 45;
- ignored files: 947.

After the CORE-001 commit and before the CFG-002 control commit:

- tracked modified files: 17;
- untracked non-ignored files: 50;
- ignored files: 947.

The ignored count is dominated by SAGA source/work copies, MongoDB runtime state, local tools,
caches, and cryptographic/runtime outputs.

## Review classes

| Class | Examples | Baseline action |
|---|---|---|
| Repository control, known CFG work | `AGENTS.md`, `.agents/`, `.codex/`, `docs/`, `agens.txt`, `.editorconfig`, `.gitattributes` | Candidate for a dedicated control-plane commit |
| Accepted CORE-001 implementation | `project/presaga/`, affected experiments and tests | Candidate for a separate core-mechanism commit after diff review |
| Active source not yet tracked | `project/scripts/check_environment.py`, `project/tests/integration/test_contact_data_binding.py` | Review and include with the matching implementation/evidence commit |
| Paper/user edits | modified and untracked files under `paper/` | Preserve; commit only in a paper work package |
| Checked-in generated evidence | dirty files under `project/results/` | Preserve; verify provenance before any experiment-evidence commit |
| Reproduction/review material | `Record/`, `comparison_reports/`, one SAGA explanation | Preserve and classify before migration |
| Unknown user material | `results/compare/*.png`, `paper/方案.zip` | Hold; never stage, move, or delete automatically |
| Temporary/ignored local state | `tmp/`, `runtime/`, `tools/`, SAGA work copies | Keep out of Git; existing material is not deleted |

## Proposed commit sequence

This is a proposal, not an executed action:

1. `feat(auth): bind Contact authorization to data-token and PRE consumption` — completed
2. `chore(repo): establish Codex control plane and canonical layout` — CFG-002 closure commit
3. `docs(paper): synchronize accepted claims and limitations`
4. `evidence(results): record only provenance-verified experiment artifacts`
5. `archive: move hash-verified legacy material` — only after explicit archive authorization

Before each commit, review the exact staged diff. Do not use `git add .` in this worktree.

## Clean-baseline completion condition

A truly clean Git worktree requires user decisions on paper edits, dirty result artifacts,
`Record/`, comparison reports, and unknown PNG/ZIP files. CFG-002 establishes the classifications
needed for those decisions but does not claim the worktree is clean while those choices remain.
