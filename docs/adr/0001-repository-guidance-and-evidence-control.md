# ADR-0001: Separate durable rules, on-demand workflow, and evidence state

- Status: accepted for `CFG-001`
- Date: 2026-07-26

## Context

The repository combines protocol code, cryptographic prototypes, experiments, formal artifacts, and
paper drafts. A single large prompt would be repeatedly loaded, consume attention, and mix stable
rules with changing milestone state. Repeated full regression runs would also create noisy evidence
without increasing confidence when relevant code has not changed.

## Decision

- Put concise, always-on rules in root `AGENTS.md`.
- Put the reusable paper-grade milestone procedure in repository skill
  `.agents/skills/presaga-paper-grade`.
- Put changing state, test history, and claim mappings under `docs/`.
- Keep the human-facing rationale and copyable master prompt in `agens.txt`; do not configure it as
  an automatic fallback instruction file.
- Limit spawned work to three subagents, favor read-heavy independent tasks, and enforce one writer
  per overlapping component.
- Select verification from change impact and require an explicit ledger reason for equivalent
  reruns.

## Consequences

New tasks load less repeated guidance while retaining strict engineering and publication gates.
Agents must update a small amount of structured state at work-package completion. The control plane
does not itself improve PRE-SAGA core behavior; a separately authorized core work package must do so.
