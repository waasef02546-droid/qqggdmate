# PRE-SAGA prototype

This directory contains the executable PRE-SAGA research prototype. It places a
data-authorization gate after SAGA-compatible contact authorization and binds a
DataToken to the exact contact session, requester registration, owner
registration, data scope, purpose, version, validity window, and usage budget.

## Evidence boundary

The implementation uses AES-256-GCM for record envelope encryption and a
versioned 1-of-1 Umbral PRE adapter over `nucypher-core==0.15.0` for the
publication-facing DEK transform. `toy_pre` and `hpke-kem-stub` remain only as
explicit protocol/defect fixtures. The active release probe snapshots the
Provider's exposed registrations, policy/token state, encrypted objects, audit
metadata, and PRE artifacts, then checks for literal DEK leakage and direct
public-key misuse while requiring successful intended-requester decryption.
Therefore:

- the bounded data-plane transform does not receive either private key,
  plaintext data, or a plaintext DEK;
- the tested concrete backend resists the repository's active public-material
  recovery probe;
- this is an exposed-state/public-API regression, not cryptanalysis, a
  security reduction, memory/side-channel analysis, independent audit, or
  whole-process guarantee.

The dependency is Alpha and GPLv3. Umbral KFrags are owner/requester key-pair
scoped, so retained-fragment reuse under Provider/requester collusion is not
excluded by the context checks. Owner rotation exports a public request and
accepts a signed artifact created outside the Provider; the owner/KMS process
still materializes the source key and DEK. See ADR 0008, ADR 0009, and the
traceability matrix before citing C-003 or C-007.

See `results/release-manifest.json` and
`docs/traceability_matrix.md` before citing a result.

## Install and test

The tested Python version is 3.12. A platform-compatible native
`nucypher-core==0.15.0` wheel is required.

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

The HTTP adapter uses `PREProviderApp` as its domain layer and the concrete
Umbral adapter by default. A JSON file is the default local persistence
backend:

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
- `POST /v1/management/agent-rotation-prepares` — prepare an owner-key rotation.
- `POST /v1/management/agent-rotation-rewrap-requests` — export a deterministic,
  non-secret owner/KMS request.
- `POST /v1/management/agent-rotation-rewraps` — stage the signed owner/KMS
  artifact; legacy `source_private_key_b64` input is rejected.
- `POST /v1/management/agent-rotation-commits`, `-aborts`, and `-cleanups` —
  finish the restart-recoverable lifecycle.
- `POST /v1/contact-sessions` — issue a contact token.
- `POST /v1/data-tokens` — evaluate data policy and issue a bound DataToken.
- `POST /v1/re-encryptions` — resolve trusted ciphertext, consume the token,
  and transform the encrypted DEK.
- `GET /v1/audit` — query audit records with optional owner, requester,
  decision, and event-type filters.
- `GET /healthz` — report service and repository recovery state.

Management endpoints use a static Bearer token in this prototype. It is not a
production identity or authorization mechanism.

### Create the owner-side rotation artifact

Save the exported request JSON and the source owner's base64 private key in a
file readable only by the owner/KMS process. The custodian also requires a
separate approval JSON created by an owner-controlled policy or operator after
checking the expected rotation, store, record, revision, and target key. Create
an artifact outside the Provider process, then submit the generated `artifact`
object to the rewrap endpoint:

```powershell
python scripts/create_owner_rewrap_artifact.py `
  --request rewrap-request.json `
  --approval owner-approved-rewrap.json `
  --source-private-key-file owner-private-key.b64 `
  --output rewrap-artifact.json
```

The private key is deliberately not accepted as a command-line value and is
never written to the artifact. The approval file is assumed to come from a
trusted local owner control; this prototype does not sign that local file or
establish its operating-system provenance. This helper is not an HSM/KMS
integration.

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

- eight expected-blocked data-layer attacks, including the concrete
  malicious-Provider public-material recovery probe;
- zero active toy-backend release paths; ToyPRE recovery remains a unit-level
  defect characterization;
- four policy-aware tool tasks;
- policy and full-service latency/scalability measurements;
- three ProVerif models with explicit true-query counting;
- two recorded-SAGA-to-PRE-SAGA bridge cases;
- one semantic owner-custody boundary probe;
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
