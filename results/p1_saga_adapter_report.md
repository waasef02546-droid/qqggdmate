# P1 SAGA-compatible adapter report

## Scope

P1 upgrades the previous SAGA-style contact policy abstraction into a
SAGA-compatible adapter layer. The prototype now separates two credentials:

- `ContactToken`: proves that a requester agent passed owner-side contact
  authorization and consumed a contact budget.
- `DataToken`: proves that the requester passed PRE-SAGA Data Sharing Policy
  for a concrete encrypted data request.

## Implemented artifacts

- `presaga/provider/saga_adapter.py`
  - AID parser for `<user-id>:<agent-name>`.
  - Contact rulebook mapping.
  - Contact budget consumption.
  - HMAC-signed contact token issuance and validation.
- `presaga/protocol/schemas.py`
  - Adds `ContactToken` while preserving the existing `DataToken`.
- `presaga/provider/app.py`
  - Provider contact entry now delegates to the SAGA-compatible adapter.
- `experiments/baselines/saga_contact_only.py`
  - Baseline now emits and validates a signed contact token, while still
    intentionally lacking PRE-SAGA data-layer control.
- `experiments/tasks/common.py`
  - Authorized task execution now validates the contact token before evaluating
    Data Sharing Policy.
- `tests/integration/test_p1_saga_adapter.py`
  - Covers AID parsing, token issuance, budget exhaustion, requester mismatch,
    expiry, Provider integration, task integration, and baseline behavior.

## Acceptance check

The P1 design keeps SAGA as the contact authorization baseline and places
PRE-SAGA only after contact authorization. This makes the comparison defensible:
SAGA-compatible contact authorization decides whether two agents may interact;
PRE-SAGA adds encrypted data sharing, data-purpose control, and proxy
re-encryption after that contact gate.

## Limitations

The adapter is intentionally local and minimal. It does not claim to reproduce
the full original SAGA Provider, OTK, DH, ACT, network transport, or runtime.
Those remain later integration work.
