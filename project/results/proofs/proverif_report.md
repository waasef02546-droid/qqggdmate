# P4 ProVerif execution report

## Purpose

This report records whether the PRE-SAGA formal artifacts were executed by ProVerif in the local environment.
It is connected to the implementation and experiments rather than being a standalone appendix:

- token acceptance proofs support the ContactToken/DataToken layering introduced in P1;
- binding proofs support the attack matrix expanded in P2;
- Provider non-plaintext visibility supports the latency/visibility evaluation reported in P3.

## Results

| Proof | Status | Output | Architecture contribution |
|---|---|---|---|
| `presaga_token_secrecy.pv` | `passed` | `presaga_token_secrecy.out.txt` | Connects P1 ContactToken/DataToken layering to P2 token misuse attacks. |
| `presaga_dek_secrecy.pv` | `passed` | `presaga_dek_secrecy.out.txt` | Connects PRE transform design to provider_plaintext_probe and P3 latency visibility boundaries. |
| `presaga_rekey_authentication.pv` | `passed` | `presaga_rekey_authentication.out.txt` | Connects requester/purpose/record/version binding to P2 stale-rekey and mismatch attacks. |

## Interpretation

All configured PRE-SAGA proof artifacts were executed by ProVerif and returned a zero exit code. Inspect each output file for the exact verifier query results.
