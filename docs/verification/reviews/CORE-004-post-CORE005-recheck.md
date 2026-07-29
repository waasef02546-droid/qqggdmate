# CORE-004 post-CORE-005 evidence recheck

- Date: 2026-07-29
- Scope: persistent rotation journal, restart recovery, terminal cleanup, and Mongo per-document CAS
- Decision: acceptance remains valid; no equivalent functional test was rerun

## Why the existing result is reusable

CORE-005 changed the Provider repository boundary and service persistence path, so its final
cross-cutting regression supersedes the earlier CORE-004 regression for the current combined core
state. That isolated run discovered 87 tests, passed all 87, used MongoDB 8.3.4 on port 27018, and
reported no skips.

The run included the CORE-004 recovery and storage coverage in:

- `project/tests/integration/test_rotation_recovery.py`
- `project/tests/integration/test_owner_key_rotation.py`
- `project/tests/integration/test_mongodb_rotation_cas.py`

It therefore exercised JSON restart restoration, commit/abort recovery, exact terminal cleanup,
idempotency, corrupt-state rejection, and live Mongo conditional updates after the CORE-005
repository and service changes were present.

FE-001 subsequently changed only `project/frontend/` and frontend evidence. Its accepted scope
explicitly excluded Provider, repository, protocol, storage, policy, token, experiment, and
paper-claim behavior. No CORE-004 or CORE-005 core/test path changed after the 87-test result.

## Interface-drift audit

- `ProviderService` restores encrypted objects before rotation journal entries, preserving the
  CORE-004 recovery validation order.
- Rotation mutations and cleanup execute through the trusted management plane and then persist the
  aggregate state.
- Mongo encrypted objects remain in their dedicated collection and retain their existing
  record-revision compare-and-swap behavior.
- Aggregate Provider metadata uses a separate revision CAS. This strengthens stale-writer failure
  detection but does not turn registration, journal, and multi-object changes into one Mongo
  transaction.

## Claim decision

Claim `C-007` remains `prototype-bounded` and requires no wording change. CORE-005 adds claim
`C-008` for the recoverable service repository boundary; it does not broaden CORE-004 into
distributed atomicity, multi-Provider linearizability, production cryptography, or HSM/KMS-backed
key management.

Repeating the same functional suite would not add evidence because the relevant implementation,
tests, configuration, environment, and command semantics have not changed. This review reuses
`CORE-005-FULL-REGRESSION` under the repository retest policy.
