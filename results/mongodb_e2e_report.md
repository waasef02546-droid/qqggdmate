# MongoDB-backed PRE-SAGA E2E report

## Scenario

Alice stores encrypted calendar availability in MongoDB. Bob obtains contact authorization, receives a policy-bound data token, obtains a transformed encrypted DEK, and decrypts only the authorized availability record. Mallory is contact-compatible but blocked by the PRE-SAGA data policy.

## Metrics

- normal_success: `True`
- attack_blocked: `True`
- denial_reason: `requester_mismatch`
- provider_plaintext_data_visible: `False`
- provider_plaintext_dek_visible: `False`
- persisted_agents: `3`
- persisted_policies: `1`
- persisted_contact_tokens: `1`
- persisted_data_tokens: `1`
- persisted_audit_events: `2`
- persisted_encrypted_objects: `1`
- latency_ms: `37.098`

## Architecture impact

This E2E supplements the in-memory prototype with persistent Provider and encrypted-object state. It does not yet reproduce the full SAGA mTLS/OTK/ACT runtime, but it closes part of the engineering gap by exercising registry, policy, token, encrypted storage, PRE transform, decryption, attack denial, and audit persistence in one MongoDB-backed flow.
