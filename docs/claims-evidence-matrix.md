# Claims–evidence matrix

This matrix prevents paper wording, implementation behavior, and evidence from drifting apart.
Statuses are intentionally conservative until a bounded work package re-audits each row.

| ID | Bounded claim | Implementation path | Current evidence | Status | Limitation / next action |
|---|---|---|---|---|---|
| C-001 | Contact authorization and data authorization are distinct gates. | `project/presaga/provider/saga_adapter.py`, `app.py`, `data_policy.py`, `token_service.py` | `test_contact_data_binding.py`; agent, HTTP, and SAGA bridge integration tests | verified | Contact authorization remains a prerequisite and does not replace the separate data-policy decision. |
| C-002 | Allowed requests can receive policy-bound data access while mismatched requester, purpose, class, or version is denied. | Provider policy/token path and policy-aware stores | Security matrix, task evaluation tables, focused tests | provisional | Confirm every reported denial is produced by the same code path used in experiments. |
| C-003 | The Provider path is designed not to recover plaintext data keys during transformation. | `project/presaga/crypto/`, encrypted storage, re-encryption path | Crypto tests and ProVerif artifacts | prototype-bounded | Toy PRE/HPKE backends do not establish production cryptographic security. |
| C-004 | Formal and experimental evidence is traceable to paper-level claims. | `project/docs/traceability_matrix.md`, `project/proofs/`, `project/results/` | Existing traceability and result artifacts | partial | Validate artifact freshness, tool availability, environment, and exact paper citations per work package. |
| C-005 | Under trusted management-plane and authenticated-AID assumptions, the single-process Provider prototype signs a DataToken to one exact Contact session, revalidates it at PRE consumption, and authorizes at most one concurrent consumption of a one-use token. | `project/presaga/protocol/schemas.py`, `provider/token_service.py`, `provider/app.py`, `provider/pre_proxy.py`, `provider/server.py` | `test_token_service.py`, `test_contact_data_binding.py`, `test_provider_http_service.py`; CORE-001 focused and isolated full regression entries | verified | The dependency-free HTTP adapter does not authenticate management endpoints or AID assertions; there is no Contact revocation, and the lock does not establish distributed multi-Provider atomicity. |

## Status vocabulary

- `verified`: implementation, repeatable evidence, and bounded wording agree.
- `provisional`: supporting artifacts exist but need work-package-level freshness or path audit.
- `partial`: only part of the stated property is evidenced.
- `unsupported`: current evidence cannot justify the wording.
- `blocked`: verification cannot proceed until a named dependency or environment issue is resolved.
