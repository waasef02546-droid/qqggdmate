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
| `presaga_token_secrecy.pv` | `tool_unavailable` | `results/proofs/presaga_token_secrecy.out.txt` | Connects P1 ContactToken/DataToken layering to P2 token misuse attacks. |
| `presaga_dek_secrecy.pv` | `tool_unavailable` | `results/proofs/presaga_dek_secrecy.out.txt` | Connects PRE transform design to provider_plaintext_probe and P3 latency visibility boundaries. |
| `presaga_rekey_authentication.pv` | `tool_unavailable` | `results/proofs/presaga_rekey_authentication.out.txt` | Connects requester/purpose/record/version binding to P2 stale-rekey and mismatch attacks. |

## Interpretation

ProVerif is not installed or not on PATH in this environment. The formal models are therefore tracked as executable artifacts, but the current run is an environment-blocked verification attempt rather than a successful proof run.

To complete P4 with real verifier output, install ProVerif and rerun:

```powershell
python -m proofs.run_proverif
```
