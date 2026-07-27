# PRE-SAGA repository instructions

## Mission

Advance this repository toward a paper-grade PRE-SAGA contribution comparable in rigor to
`local_conversation_management/2504.21034v2.pdf`. Treat the paper, implementation, experiments,
formal artifacts, and reproducibility record as one evidence system. Never improve the prose by
making a claim stronger than the code or evidence.

## Instruction routing

- This file contains durable, always-on repository rules. Keep it concise.
- For a bounded research or engineering milestone, use the repository skill
  `$presaga-paper-grade`.
- Read `docs/workflow/current-milestone.md` before substantive work.
- Read `docs/verification/test-ledger.yaml` before rerunning tests or experiments.
- Use `agens.txt` as the human-facing design and prompt manual; it is not an auto-loaded
  instruction file.

## Work-package discipline

- Work on one accepted work package at a time. Define its objective, non-goals, affected core
  modules, acceptance criteria, evidence obligations, and risks before implementation.
- Resolve facts from repository files and available tools instead of asking the user to repeat
  discoverable information.
- Ask for user direction only when a missing choice materially changes scope, scientific claims,
  architecture, destructive actions, or external side effects.
- Do not silently begin the next work package after completing the current one.

## Core-code priority

- For engineering milestones, the primary output must be behaviorally meaningful core-code
  progress in `project/presaga/`, `project/experiments/`, or `project/proofs/`.
- Tests support changed behavior; they are not a substitute for implementation. Do not create a
  test-only milestone unless the authorized objective is explicitly verification, reproduction,
  or defect characterization.
- Prefer the smallest coherent production path over broad scaffolding. Preserve honest prototype
  boundaries: toy PRE/HPKE stubs must never be described as production cryptography.

## Verification and evidence

- Select tests from change impact. Consult
  `.agents/skills/presaga-paper-grade/references/retest-policy.md`.
- Before running a test or experiment, check the ledger for the same target, relevant code state,
  configuration, and environment. Do not repeat an equivalent successful run unless:
  1. affected core code or configuration changed;
  2. a prior result was invalid or flaky;
  3. a release/full-regression gate requires it; or
  4. the rerun reason is recorded.
- New or changed behavior requires focused positive, negative, and boundary verification.
- Run the full suite only for cross-cutting API/schema changes, substantial refactors, release
  gates, or evidence that targeted checks are insufficient.
- Record commands, result, affected work package, evidence paths, and rerun reason in
  `docs/verification/test-ledger.yaml`.
- Update `docs/claims-evidence-matrix.md` whenever a paper claim, security property, limitation,
  implementation path, or supporting artifact changes.

## Multi-agent efficiency

- The primary agent owns scope, architecture decisions, integration, and the final evidence chain.
- Use subagents only when at least two bounded tasks are genuinely independent. Prefer parallel
  exploration, evidence review, test/log analysis, and non-overlapping component work.
- Use at most three concurrent subagents. Assign one owner per overlapping code area; never allow
  parallel edits to the same files.
- Each subagent must return conclusions, file references, risks, and recommended action—not raw
  logs or a narration of every step.
- Stay single-agent for small, sequential, or tightly coupled work where coordination would cost
  more than execution.

## Completion gate

A work package is complete only when:

- the authorized behavior is implemented;
- focused verification passes or blockers are evidenced;
- generated evidence is reproducible and linked;
- claims and limitations match the implementation;
- the test ledger and current milestone are updated; and
- remaining risks and the proposed next work package are explicit.

Use `.agents/skills/presaga-paper-grade/scripts/check_repo_workflow.py --root .` to validate the
repository control files after changing them.
