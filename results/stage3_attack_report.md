# Stage 3 Attack Experiment Report

## Purpose

This report records the stage 3 security experiment status for the PRE-SAGA prototype.

The key design point is that each implemented attack first passes a lightweight SAGA-style contact gate. Therefore, the attacks are not rejected merely because the requester cannot contact the owner agent. They are rejected by PRE-SAGA's data-layer controls: Data Sharing Policy, data-token binding, usage limits, or requester binding.

## Baseline Relationship

The current prototype does not embed the full SAGA implementation. Instead, it models the SAGA baseline interface that PRE-SAGA depends on:

```text
SAGA-style Contact Policy:
  decides whether requester agent may contact owner agent

PRE-SAGA Data Sharing Policy:
  decides whether requester agent may decrypt a specific data object
```

This is sufficient for stage 3 because the security experiments are designed to show that:

```text
contact allowed != data decryption allowed
```

The full SAGA code path should still be integrated in a later stage if the paper targets a stronger systems venue.

## Implemented Attacks

| Attack | Script | Expected control point |
|---|---|---|
| Unauthorized data class | `experiments/attacks/unauthorized_data_class.py` | Data Sharing Policy |
| Purpose mismatch | `experiments/attacks/purpose_mismatch.py` | Data token purpose binding |
| Token reuse | `experiments/attacks/token_reuse.py` | Token max-use limit |
| Requester mismatch | `experiments/attacks/requester_mismatch.py` | Requester identity binding |

## Run Command

```powershell
cd project
python -m experiments.attacks.run_all
```

## Output

The generated matrix is:

```text
project/results/tables/security_matrix.csv
```

## Current Result Summary

All four attacks are blocked after contact is allowed.

| Attack | Blocked reason | Strength |
|---|---|---|
| Unauthorized data class | `data_class_denied` | Shows SAGA contact permission is insufficient for data-class access. |
| Purpose mismatch | `purpose_mismatch` | Issues a valid token first, then misuses it with another purpose. |
| Token reuse | `token_exhausted` | Allows the first transform and rejects replay after max-use exhaustion. |
| Requester mismatch | `requester_mismatch` | Allows another agent at contact layer but rejects use of Bob's data token. |

## Strength Assessment

The experiments are stronger than pure unit tests because they test abuse after a valid contact gate, and in two cases after a valid data token has already been issued.

Remaining gaps:

- Stale rekey / version mismatch is covered by unit tests but not yet by a standalone attack script.
- Provider plaintext probe is covered by integration assertions but not yet by a standalone attack script.
- Metadata linkage and compromised requester are currently discussion-level limitations, not automated attacks.

## Acceptance Status

Stage 3 minimum scope is satisfied for the four required attacks. The results support the paper claim that PRE-SAGA adds data-decryption governance beyond SAGA contact governance.
