# Stage 4 Formal Artifact Report

## Scope

Stage 4 requires formal-analysis-oriented artifacts. The current implementation adds ProVerif-style symbolic model files under `proofs/`.

This stage does not claim a completed machine-checked proof because ProVerif is not bundled with the current runtime. Instead, the project now has reviewable model files and automated smoke tests that check whether the required security goals, events, and boundary statements are present.

## Deliverables

| Deliverable | Path | Status |
|---|---|---|
| DEK secrecy model | `proofs/presaga_dek_secrecy.pv` | Added |
| Rekey authentication model | `proofs/presaga_rekey_authentication.pv` | Added |
| Proof artifact README | `proofs/README.md` | Added |
| Formal artifact smoke tests | `tests/security/test_formal_artifacts.py` | Added |

## Goals Covered

- Provider / PRE Proxy should not learn plaintext DEK.
- Transform issuance should imply a prior policy allow event.
- Re-encryption acceptance should imply a matching token issuance event.
- Requester, record, data class, purpose, and version mismatch cases are modeled as rejected paths.

## Current Boundary

- No concrete PRE primitive is proved.
- The toy PRE backend is explicitly outside the cryptographic proof claim.
- Endpoint compromise and requester plaintext exfiltration are out of scope.
- Metadata privacy against Provider is not proved.

## Next Improvement

Install ProVerif or run these models in a separate verification environment, then record actual verifier output under `results/raw/`.
