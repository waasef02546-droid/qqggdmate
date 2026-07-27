# PRE-SAGA

PRE-SAGA is a research prototype that separates two decisions in multi-agent systems:

1. **Contact authorization** — whether one agent may contact another.
2. **Data authorization** — whether that contact may obtain a narrowly scoped decryption result.

The project extends a reproduced SAGA contact layer with Data Sharing Policy, encrypted storage,
policy-bound data tokens, and proxy re-encryption orchestration. The current cryptographic backends
remain toy/stub implementations and do not establish production cryptographic security.

## Authoritative repository entry points

- `project/` — the only authoritative PRE-SAGA engineering tree.
- `project/presaga/` — protocol, Provider, policy, token, cryptography, storage, and agent runtime.
- `project/experiments/` — baselines, attacks, end-to-end scenarios, evaluation, and performance.
- `project/proofs/` — formal models and verifier runners.
- `project/tests/` — verification for changed behavior.
- `project/results/` — checked-in experiment evidence; do not overwrite without an authorized
  experiment work package.
- `paper/` — paper drafts, figures, plans, and limitations.
- `docs/` — repository workflow, ADRs, verification ledger, claims matrix, and repository maps.
- `saga_reproduction/` — SAGA baseline reproduction evidence and local compatibility notes.

Root-level `prototype/`, `runtime/`, `tools/`, `results/`, `Record/`, `comparison_reports/`, and
`project/result/` are not authoritative implementation entry points. They are classified in
`docs/repository/archive-manifest.yaml` and must not be deleted or moved without a reference audit
and an explicitly approved archive operation.

## Codex workflow

- Durable rules: `AGENTS.md`
- Human prompt manual: `agens.txt`
- Paper-grade workflow: `.agents/skills/presaga-paper-grade/SKILL.md`
- Current work package: `docs/workflow/current-milestone.md`
- Test/experiment history: `docs/verification/test-ledger.yaml`
- Claim-to-evidence status: `docs/claims-evidence-matrix.md`

Use one authorized work package at a time. Core implementation precedes tests; tests provide
evidence for changed behavior.

## Local validation

From the repository root:

```powershell
python .agents/skills/presaga-paper-grade/scripts/check_repo_workflow.py --root .
```

This validates repository control files only. Functional tests and experiments are selected from
change impact and the test ledger.

On Windows PowerShell 5.1, read UTF-8 documents explicitly:

```powershell
Get-Content -Encoding UTF8 .\agens.txt
```

The repository encoding rules are recorded in `.editorconfig` and `.gitattributes`.
