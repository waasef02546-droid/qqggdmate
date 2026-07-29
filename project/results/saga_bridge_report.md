# SAGA baseline to PRE-SAGA bridge report

This artifact does not claim that PRE-SAGA started a live SAGA socket. It imports recorded SAGA reproduction evidence, then executes the PRE-SAGA data-layer extension for the same Alice/Bob/Mallory narrative.

## Evidence boundary

The listed baseline paths are recorded terminal outputs for SAGA Provider access, certificate-verified communication, token issuance, quota consumption, and invalidation. PRE-SAGA results below are local extension results, not retroactive claims about the SAGA implementation.

## Cases

### alice_bob_authorized_calendar

- SAGA baseline evidence: `saga_reproduction/saga_e2e_terminal_output.txt`
- Baseline conclusion: Alice and Bob completed certificate-verified contact, token issuance, quota consumption, and token invalidation.
- SAGA contact allowed: `True`
- PRE-SAGA data decision: `allow` (policy_match)
- Plaintext released: `True`
- Provider saw plaintext data/DEK: `False` / `False`

### alice_mallory_contact_allowed_data_denied

- SAGA baseline evidence: `saga_reproduction/saga_multi_agent_terminal_output.txt`
- Baseline conclusion: Alice accepted separately authorized Bob and Mallory contact sessions; both consumed and invalidated SAGA tokens.
- SAGA contact allowed: `True`
- PRE-SAGA data decision: `deny` (requester_mismatch)
- Plaintext released: `False`
- Provider saw plaintext data/DEK: `False` / `False`

## Interpretation

Bob's already-authorized contact session obtains the narrowly scoped calendar availability record. Mallory's SAGA-compatible contact session is intentionally allowed, but the PRE-SAGA data policy denies the same record because the policy binds access to Bob's AID. This is the measured contact-layer/data-layer separation; it is not a claim that SAGA itself exposes or stores this calendar record.
