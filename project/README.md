# PRE-SAGA prototype

This directory contains the executable PRE-SAGA research prototype. It places a
data-authorization gate after SAGA-compatible contact authorization and binds a
DataToken to the exact contact session, requester registration, owner
registration, data scope, purpose, version, validity window, and usage budget.

## Evidence boundary

The implementation uses AES-256-GCM for record envelope encryption. The bundled
`toy_pre` and `hpke-kem-stub` transform backends are deterministic protocol
stubs, not production PRE/HPKE. The active release probe demonstrates that
ToyPRE allows DEK recovery from public material. Therefore:

- the service control flow does not explicitly pass plaintext data or a
  plaintext DEK into the transform;
- the current concrete backend does **not** establish cryptographic Provider
  confidentiality;
- audit visibility fields are instrumentation, not a security proof.

See `results/release-manifest.json` and
`docs/traceability_matrix.md` before citing a result.

## Install and test

The supported Python version is 3.10 or newer.

```powershell
cd project
python -m pip install -e .
python -m unittest discover -s tests -v
```

Mongo integration tests use `PRESAGA_MONGODB_URI` when a local MongoDB service
is available:

```powershell
$env:PRESAGA_MONGODB_URI = "mongodb://127.0.0.1:27017"
python -m unittest discover -s tests -v
```

## Run the Provider service

The dependency-free HTTP adapter uses `PREProviderApp` as its domain layer. A
JSON file is the default local persistence backend:

```powershell
$env:PRESAGA_MANAGEMENT_TOKEN = "replace-with-a-local-secret"
python -m presaga.provider.server `
  --host 127.0.0.1 `
  --port 8080 `
  --state-file provider-state.json
```

For MongoDB:

```powershell
$env:PRESAGA_MANAGEMENT_TOKEN = "replace-with-a-local-secret"
python -m presaga.provider.server `
  --host 127.0.0.1 `
  --port 8080 `
  --mongo-uri mongodb://127.0.0.1:27017 `
  --mongo-db presaga_provider
```

Mongo startup never resets the selected database. Every service mutation
advances an aggregate `state_revision`; a stale writer that loses the
compare-and-swap is fenced until restart. Aggregate metadata and encrypted
objects remain separate atomicity domains. This is not a distributed
transaction or leader-election claim.

Principal endpoints:

- `POST /v1/management/agents` — register an AID and public key.
- `POST /v1/management/contact-rulebooks` — configure contact policy.
- `POST /v1/management/data-policies` — add a Data Sharing Policy.
- `POST /v1/management/agent-rotation-*` — drive the authenticated,
  restart-recoverable owner-key rotation lifecycle.
- `POST /v1/contact-sessions` — issue a contact token.
- `POST /v1/data-tokens` — evaluate data policy and issue a bound DataToken.
- `POST /v1/re-encryptions` — resolve trusted ciphertext, consume the token,
  and transform the encrypted DEK.
- `GET /v1/audit` — query audit records with optional owner, requester,
  decision, and event-type filters.
- `GET /healthz` — report service and repository recovery state.

Management endpoints use a static Bearer token in this prototype. It is not a
production identity or authorization mechanism.

## Run the authoritative release

The full release profile requires MongoDB and real ProVerif output. It writes
to a unique staging directory, evaluates all gates, verifies source/config and
artifact hashes, then publishes the manifest last:

```powershell
$env:PRESAGA_MONGODB_URI = "mongodb://127.0.0.1:27017"
python -m experiments.run_all
python scripts/verify_release.py
```

`results/release-manifest.json` is the authority for the accepted artifact set.
Unlisted result files are historical or auxiliary.

The release covers:

- seven expected-blocked data-layer attacks;
- one expected-success ToyPRE limitation probe;
- four policy-aware tool tasks;
- policy and full-service latency/scalability measurements;
- three ProVerif models with explicit true-query counting;
- two recorded-SAGA-to-PRE-SAGA bridge cases;
- one recoverable MongoDB Provider E2E.

Timing is descriptive local evidence. It is not a security proof or a
cross-machine performance claim.

## Standalone evidence commands

```powershell
python -m proofs.run_proverif
python -m experiments.e2e.saga_bridge
python -m experiments.e2e.mongodb_e2e
```

The SAGA bridge reads recorded SAGA terminal evidence and runs the PRE-SAGA
extension through `ProviderService`; it does not start a live SAGA socket or
claim full runtime interoperability.
