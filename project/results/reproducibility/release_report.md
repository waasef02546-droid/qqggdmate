# PRE-SAGA authoritative release report

- Run ID: `20260729T123951Z-23c9fbf1`
- Profile: `full`
- Source fingerprint: `fc8c5a40159d622cca1830dc0f25582d2f76a32a4e146e7f19fbefc80e8af195`
- Git HEAD: `6109b3eb6318a9714ee29b65da2340be5a6abcdf`
- Release inputs dirty: `False`
- Other workspace changes present: `True`
- Task success: `4/4`

## Acceptance gates

| Gate | Passed | Observation |
|---|---:|---|
| `blocking_attacks` | `True` | 7/7 |
| `prototype_limitation_probe` | `True` | 1 active probe(s) |
| `task_success` | `True` | 4/4 |
| `performance_rows` | `True` | 12/12 |
| `proverif_queries` | `True` | presaga_token_secrecy.pv:passed:1,presaga_dek_secrecy.pv:passed:2,presaga_rekey_authentication.pv:passed:1 |
| `saga_bridge` | `True` | 2 case(s) |
| `mongodb_e2e` | `True` | required |
| `release_inputs_clean` | `True` | clean |

## Evidence boundary

- ToyPRE and HPKEKEMStub are deterministic prototype backends, not production cryptography.
- The active limitation probe recovers the ToyPRE DEK from public material; cryptographic Provider confidentiality is not established.
- Provider plaintext visibility booleans are control-flow instrumentation, not a confidentiality proof.
- The SAGA bridge consumes recorded SAGA evidence and does not run a live SAGA network.
- MongoDB evidence is single-node local persistence and does not establish distributed transactions, RAFT, or sharding.
- ProVerif models cover their explicit symbolic queries only and do not verify the complete Python implementation.
- Artifact integrity is checked relative to the manifest; the manifest is not cryptographically signed or externally witnessed.

The JSON manifest is the authority for artifact hashes, source identity, configuration, environment, and gate results. Files not listed by that manifest are historical or auxiliary and are not part of this accepted run.
