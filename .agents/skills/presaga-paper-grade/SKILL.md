---
name: presaga-paper-grade
description: Drive paper-grade PRE-SAGA research implementation from a bounded work package through core-code changes, targeted verification, experiment evidence, and claim updates. Use for protocol, policy, token, cryptography, storage, evaluation, formal-proof, reproducibility, or paper-claim milestones in this repository, especially when preventing test-only progress and duplicate reruns.
---

# PRE-SAGA Paper Grade

## Start with the control state

1. Read the repository `AGENTS.md`.
2. Read `docs/workflow/current-milestone.md`.
3. Read `docs/claims-evidence-matrix.md`.
4. Read `docs/verification/test-ledger.yaml` before selecting any test or experiment.
5. State the active work package in a compact form: objective, non-goals, affected core path,
   acceptance criteria, evidence obligations, and risks.

If the request would materially change the active scope or scientific claim, ask for authorization.
Do not ask for facts that can be resolved from the repository or available tools.

## Execute a core-first work package

1. Trace the behavior from external request to server-enforced decision, cryptographic/storage
   action, observable result, and paper claim.
2. Identify the smallest coherent core-code change that can satisfy the accepted behavior.
3. Implement the behavior before expanding tests or prose.
4. Preserve explicit prototype limitations; never convert a control-flow stub into a cryptographic
   security claim.
5. Add or update only the verification needed for the changed normal, denial, and boundary paths.

Tests are evidence for implementation. A test-only result is acceptable only when the authorized
work package is explicitly an audit, reproduction, formal-verification, or defect-characterization
task.

## Choose parallelism deliberately

Use subagents only when at least two tasks are independent and bounded. Prefer read-heavy
exploration, security review, evidence audit, or non-overlapping implementation. Use no more than
three subagents and one writer per overlapping component. Keep architecture and final integration
with the primary agent. Require distilled conclusions with file references rather than raw logs.

Stay single-agent when the work is small, sequential, or coupled through an unresolved design
decision.

## Verify by change impact

Read [retest-policy.md](references/retest-policy.md). Check the ledger before running anything.
Choose the smallest set that can falsify the changed behavior. Record an explicit reason for every
equivalent rerun. Do not run the entire suite for documentation, guidance, or isolated unchanged
paths.

After changing repository control files, run:

```powershell
python .agents/skills/presaga-paper-grade/scripts/check_repo_workflow.py --root .
```

This validates only the control plane and never substitutes for PRE-SAGA functional verification.

## Close the evidence loop

Read [acceptance-gates.md](references/acceptance-gates.md) and iterate within the same work package
until each applicable gate passes or a blocker has concrete evidence.

Before reporting completion:

- update `docs/verification/test-ledger.yaml`;
- update `docs/claims-evidence-matrix.md` if behavior, evidence, wording, or limitations changed;
- update `docs/workflow/current-milestone.md` with state, residual risks, and a proposed next package;
- link exact implementation and evidence paths;
- distinguish verified, provisional, partial, unsupported, and blocked claims; and
- stop before implementing the next work package without user authorization.

Report only the core outcome, verification evidence, claim impact, residual risks, and next proposed
decision.
