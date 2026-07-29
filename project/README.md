# PRE-SAGA Prototype

This directory contains the PRE-SAGA prototype implementation.

The prototype implements a SAGA-compatible contact authorization layer followed
by PRE-SAGA data sharing:

- SAGA-compatible contact token adapter
- Data Sharing Policy evaluator
- data token service
- policy-aware mail, calendar, document, and memory stores with record filtering and field projection
- toy PRE interface
- attack matrix
- task-level evaluation
- MongoDB-backed E2E persistence experiment
- formal-analysis runner

The data-encryption path uses standard AES-256-GCM envelope encryption with a
fresh 96-bit nonce and record-bound associated data.  The bundled `toy_pre` and
`hpke-kem-stub` key-transform backends remain deliberately insecure protocol
stubs: they validate authorization bindings and control flow only, and are not
production PRE/HPKE implementations.  A reviewed PRE or HPKE adapter is still
required before protecting real keys or data.

## Run tests

```powershell
cd project
python -m unittest discover -s tests -v
```

## Run the local Provider service

The dependency-free HTTP service keeps `PREProviderApp` as the domain layer and
uses a JSON file for local persistent Provider state.  It is intended for the
prototype/E2E workflow, not as a production authentication service.

```powershell
cd project
$env:PRESAGA_MANAGEMENT_TOKEN = "replace-with-a-local-secret"
python -m presaga.provider.server --host 127.0.0.1 --port 8080 --state-file provider-state.json
```

The service creates a trusted encrypted-object store and persists schema-v3 registrations,
encrypted objects, and rotation history in the state file. All `/v1/management/*` requests require
`Authorization: Bearer <PRESAGA_MANAGEMENT_TOKEN>`.

The principal JSON APIs are:

- `POST /v1/management/agents` — `{aid, public_key_b64}` registers an agent.
- `POST /v1/management/agent-rotation-preparations`, `agent-rotation-rewraps`,
  `agent-rotation-commits`, `agent-rotation-aborts`, and `agent-rotation-cleanups` — drive the
  authenticated, restart-recoverable owner-key lifecycle.
- `POST /v1/management/contact-rulebooks` — configures the SAGA-compatible contact policy.
- `POST /v1/management/data-policies` — adds a `DataSharingPolicy`.
- `POST /v1/contact-sessions` — `{owner_aid, requester_aid}` issues a contact token.
- `POST /v1/data-tokens` — accepts a data-access request and returns a policy decision and, if allowed, a data token.
- `POST /v1/re-encryptions` — `{token_id, request, rekey_b64}` resolves the trusted stored object,
  validates provenance, and consumes a token before transforming the encrypted DEK.
- `GET /v1/audit` — returns audit records; optional `owner_aid`, `requester_aid`, `decision`, and `event_type` query filters are supported.

`GET /healthz` provides a lightweight service-health endpoint.

## Expected result

All tests should pass. The tests cover:

- SAGA-compatible contact token issuance and validation
- allowed data sharing
- data class denial
- purpose mismatch
- requester mismatch
- data version mismatch
- token max-use exhaustion
- encrypted store round trip
- PRE transform without Provider plaintext DEK exposure
- task-level evaluation artifact generation
- ProVerif runner output tracking

## Run all experiments

```powershell
cd project
python -m experiments.run_all
```

The combined runner generates or refreshes:

```text
results/tables/security_matrix.csv
results/tables/task_results.csv
results/tables/task_summary.csv
results/tables/denial_reason_summary.csv
results/tables/task_latency_breakdown.csv
results/tables/task_scalability.csv
results/tables/mongodb_e2e_summary.csv
results/tables/saga_bridge_summary.csv
results/mongodb_e2e_report.md
results/saga_bridge_report.md
results/proofs/proverif_summary.csv
```

The attack scripts intentionally run after a SAGA-compatible contact gate allows
the requester. This shows that PRE-SAGA blocks data-layer abuse even when
contact is permitted.

## Run formal-analysis artifacts

```powershell
cd project
python -m proofs.run_proverif
```

If ProVerif is installed and on PATH, the runner saves real verifier output
under `results/proofs/`. If it is not installed, the runner records
`tool_unavailable` so the verification status remains auditable.

## Traceability from formal claims to code and evidence

[`docs/traceability_matrix.md`](docs/traceability_matrix.md) maps each
paper-level security claim to the ProVerif event/query, protocol fields,
implementation path, and repeatable test or attack experiment.  The matrix
also states the prototype boundary: it does not treat the toy PRE backend as a
concrete cryptographic proof.

```powershell
cd project
python -m unittest tests.security.test_traceability -v
```

## Run MongoDB-backed E2E

Start a local MongoDB instance on `127.0.0.1:27017`, then run:

```powershell
cd project
python -m experiments.e2e.mongodb_e2e
```

The E2E persists agent registry state, data policies, contact tokens, data tokens, audit events,
and encrypted objects in MongoDB. The CORE-004 rotation test additionally exercises journal-state
and object-revision compare-and-swap updates:

```powershell
$env:PRESAGA_MONGODB_URI = "mongodb://127.0.0.1:27017"
python -m unittest tests.integration.test_mongodb_rotation_cas -v
```

## Run the SAGA-to-PRE-SAGA bridge

```powershell
cd project
python -m experiments.e2e.saga_bridge
```

The bridge does not start a SAGA socket or claim direct runtime compatibility.
It reads the recorded SAGA Alice/Bob and Alice/Bob/Mallory terminal evidence
under `../saga_reproduction/`, then runs a PRE-SAGA data-layer extension for
the same narrative.  The output distinguishes a normal Bob calendar release
from a Mallory case where SAGA-style contact is allowed but PRE-SAGA data access
is denied.  It writes:

```text
results/tables/saga_bridge_summary.csv
results/saga_bridge_report.md
```
