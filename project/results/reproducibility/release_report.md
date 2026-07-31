# PRE-SAGA authoritative release report

- Run ID: `20260731T111704Z-c1d0f804`
- Profile: `full`
- Source fingerprint: `b63f2e09a6503346f7e62b4e9fe82ce27afa5b0c6651f727b225ee86a5fb2595`
- Git HEAD: `5f1cea694249397095672867d087daab4630be36`
- Release inputs dirty: `False`
- Other workspace changes present: `True`
- Task success: `4/4`

## Acceptance gates

| Gate | Passed | Observation |
|---|---:|---|
| `blocking_attacks` | `True` | 8/8 |
| `prototype_limitation_probe` | `True` | 0 active probe(s) |
| `concrete_provider_recovery_probe` | `True` | Provider exposed-state regression found no DEK, public-key unwrap was rejected, and requester decrypt verified |
| `task_success` | `True` | 4/4 |
| `performance_rows` | `True` | 12/12 |
| `proverif_queries` | `True` | presaga_token_secrecy.pv:passed:1,presaga_dek_secrecy.pv:passed:2,presaga_rekey_authentication.pv:passed:1 |
| `saga_bridge` | `True` | 2 case(s) |
| `key_custody_boundary` | `True` | trusted owner-local approval rejects target substitution; signed artifact accepted; replay bounded; legacy private-key input rejected; target decrypt succeeded; no source key or plaintext DEK found in bounded Provider-visible surfaces |
| `mongodb_e2e` | `True` | required |
| `release_inputs_clean` | `True` | clean |

## Evidence boundary

- The release backend is the prototype Umbral adapter over nucypher-core 0.15.0 (Alpha, GPLv3); it has not been independently audited and is not production cryptography.
- The active malicious-Provider regression finds no raw/base64/hex DEK in the exposed state, rejects direct public-key unwrap misuse, and confirms requester decryption; it is not cryptanalysis, a reduction, memory/side-channel analysis, or a whole-process guarantee.
- Umbral KFrags are owner/requester key-pair scoped. Provider/requester collusion and retained KFrag reuse across same-owner capsules remain outside the established claim.
- Owner-key rotation removes the source private key and plaintext DEK from Provider interfaces and persisted/exported Provider state; the owner/KMS process still materializes them, and HSM isolation, memory forensics, side-channel resistance, and a whole-process guarantee are not established.
- The owner/KMS CLI requires an exactly matching owner-local approval file, but the prototype does not sign that file or authenticate its operating-system provenance; a compromised owner host is outside the established boundary.
- The SAGA bridge consumes recorded SAGA evidence and does not run a live SAGA network.
- MongoDB evidence is single-node local persistence and does not establish distributed transactions, RAFT, or sharding.
- ProVerif models cover their explicit symbolic queries only and do not verify the complete Python implementation.
- Artifact integrity is checked relative to the manifest; the manifest is not cryptographically signed or externally witnessed.

The JSON manifest is the authority for artifact hashes, source identity, configuration, environment, and gate results. Files not listed by that manifest are historical or auxiliary and are not part of this accepted run.
