# Paper-grade acceptance gates

Apply only gates relevant to the active work package, but never omit a relevant security or evidence
gate for speed.

## 1. Scope and design gate

- The objective is one falsifiable behavior or bounded research conclusion.
- Non-goals and affected core modules are explicit.
- Trust assumptions, attacker capability, protected asset, and failure behavior are stated.
- Acceptance criteria include normal, denial/attack, boundary, and reproducibility expectations.
- The proposed mechanism maps to one or more claims in the claims–evidence matrix.

## 2. Core implementation gate

- The property is enforced in the authoritative protocol/Provider/crypto/storage path, not only in a
  client, fixture, or test mock.
- Inputs and identities are bound where the decision is made.
- Failure is closed and observable without leaking protected material.
- Compatibility and migration effects are explicit.
- Toy, stub, simulation, and production boundaries remain visible in code and prose.

## 3. Verification gate

- Focused tests can fail for the intended bug or missing behavior.
- Positive, denial, tamper/replay where relevant, and boundary paths are covered.
- Test choice follows the retest policy and checks the ledger first.
- Commands, environment, result, and artifact paths are recorded.
- Full regression is used only when change impact or a release gate justifies it.

## 4. Experiment and formal-evidence gate

- Metrics correspond to the mechanism and research question.
- Dataset, seeds, configuration, environment, and external service/tool availability are recorded.
- Generated tables/figures are traceable to a command and source artifact.
- Formal claims name the modeled property and assumptions; unavailable tools are reported as
  unavailable, not as a passing proof.

## 5. Paper claim gate

- Wording does not exceed the implementation, experiment, or model.
- Each important claim has an implementation path and repeatable evidence.
- Limitations and threats to validity are explicit.
- Negative or null results remain visible.

## 6. Closure gate

- The active work package state and residual risks are updated.
- The ledger and claims matrix are current.
- No unrelated next milestone was silently started.
- The final report separates verified facts, inferences, and proposed next work.
