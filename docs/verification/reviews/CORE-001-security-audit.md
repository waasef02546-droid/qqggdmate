# CORE-001 independent security audit

- Date: 2026-07-26
- Mode: read-only independent subagent review followed by primary-agent remediation
- Scope: Contact authorization to DataToken issuance to PRE re-encryption consumption
- Initial result: no P0; one P1 boundary issue and two P2 implementation/evidence issues
- Closure result: accepted with explicit prototype assumptions and residual risks; final read-only
  recheck found no remaining P0-P2

## Findings and disposition

| Severity | Finding | Disposition |
|---|---|---|
| P1 | The dependency-free HTTP adapter does not authenticate registration, rulebook, policy, Contact-session, or AID assertions. An unconditional “attacker may directly call every endpoint” claim would exceed the implementation. | Accepted as an explicit prototype boundary, not hidden. ADR 0002, the milestone, and claim C-005 now require a trusted management plane and authenticated AID assertions. Production identity transport remains a separate work package. |
| P2 | Several experiment runners directly invoked the low-level TokenService issuance method and could bypass the authoritative App policy/Contact sequence. | Remediated. Low-level issuance is private-by-convention (`_issue_data_token`), and attack, scalability, and performance experiments now issue and consume through `PREProviderApp`. Direct calls remain only in TokenService-focused tests. |
| P2 | Evidence did not directly cover legacy unbound tokens, missing bound Contact state, or replay after persistence/restart. | Remediated. Focused integration tests now cover all three. The existing concurrent one-use test continues to cover process-local atomic consumption. |

A second review noted that some attacks and the baseline still called `app.proxy` directly and that
the first legacy test did not cross JSON restore. Both were corrected: every experiment now calls
`PREProviderApp.request_re_encryption()`, and the legacy test saves through
`JsonProviderRepository`, restores through `ProviderService`, and verifies server-side rejection.
The final independent recheck found no remaining P0-P2.

## Confirmed properties

- HTTP data-token issuance resolves Contact state server-side and the App checks Contact signature,
  expiry, owner, requester, and the separate data policy.
- The DataToken signature covers Contact token ID and Contact session reference.
- DataToken expiry is capped by both policy and Contact expiry.
- PRE consumption revalidates the server-resolved bound Contact and rejects missing, forged,
  expired, or different sessions.
- Validation and use decrement are atomic within one TokenService process.
- Legacy unbound tokens fail closed.
- Representative experiments use the same authoritative App issuance and consumption path.

## Residual risks

- HTTP management and AID authentication are not implemented.
- Atomicity is process-local and JSON persistence is not a distributed transaction.
- Contact revocation is not implemented.
- PRE backend failure occurs after token consumption and therefore spends one use.
- Default local issuer secrets and toy cryptographic backends are prototype-only.
- `paper/threat_model.md` still needs the trusted-management and authenticated-AID assumptions
  synchronized during a future paper-claim work package; paper rewriting was outside `CORE-001`.

## Verification after remediation

- Focused acceptance: 29 tests passed.
- Isolated full regression: 59 tests total; 58 passed and one MongoDB E2E test skipped because the
  local service was unavailable.
- Repository workflow checker passed.
