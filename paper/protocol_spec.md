# PRE-SAGA Protocol Specification

## 1. Scope

PRE-SAGA extends SAGA from contact-level governance to data-decryption-level governance.

SAGA answers:

> May requester agent `A_r` contact owner agent `A_o`?

PRE-SAGA additionally answers:

> After contact is allowed, may requester agent `A_r` obtain a decryptable form of data object `D_i` under a declared purpose, time window, usage bound, and data version?

The design goal is not to introduce a new proxy re-encryption primitive. The goal is to define a concrete system protocol that combines:

- SAGA-style agent identity and contact authorization;
- envelope encryption for local agent data;
- Data Sharing Policy for data-object-level authorization;
- Provider / PRE Proxy mediated re-encryption;
- audit logging for every data authorization decision.

## 2. Entities

### 2.1 User

The human or organization that owns one or more agents.

Fields:

```text
uid: string
user_public_signing_key: bytes
user_certificate: bytes
```

Responsibilities:

- registers agents;
- defines contact policy;
- defines data sharing policy;
- authorizes agent data ownership and policy updates.

### 2.2 Owner Agent

The agent that owns encrypted local data.

Notation:

```text
A_o
```

Fields:

```text
owner_aid: string
owner_public_identity_key: bytes
owner_public_encryption_key: bytes
owner_agent_certificate: bytes
contact_policy_ref: string
data_policy_ref: string
```

Responsibilities:

- stores data as ciphertext;
- encrypts each data object with a data encryption key;
- registers encrypted data metadata with Provider / PRE Proxy;
- authorizes Data Sharing Policy;
- may rotate DEKs and data versions.

### 2.3 Requester Agent

The agent requesting access to another agent's encrypted data.

Notation:

```text
A_r
```

Fields:

```text
requester_aid: string
requester_public_identity_key: bytes
requester_public_encryption_key: bytes
requester_agent_certificate: bytes
```

Responsibilities:

- obtains contact authorization through SAGA baseline;
- sends a data access request with purpose, data scope, and requested operation;
- receives a re-encrypted encrypted data key or a re-encrypted ciphertext view;
- decrypts only the authorized object or authorized data projection.

### 2.4 Provider / PRE Proxy

The policy enforcement and re-encryption mediation component.

Notation:

```text
P
```

Responsibilities:

- maintains agent registry;
- evaluates contact authorization by reusing SAGA-style contact policy;
- evaluates Data Sharing Policy;
- validates token binding fields;
- performs PRE transform or dispatches to a PRE backend;
- records audit logs;
- must not learn plaintext data or plaintext DEK.

Provider-visible information:

```text
owner_aid
requester_aid
record_id
data_class
purpose
policy_id
token_id
data_version
timestamps
decision
rejection_reason
```

Provider-hidden information:

```text
plaintext data
plaintext DEK
requester private keys
owner private keys
```

### 2.5 Encrypted Store

The storage layer for owner agent data.

Responsibilities:

- stores ciphertext records;
- stores encrypted DEKs;
- stores metadata needed for policy evaluation;
- never exposes plaintext to Provider.

The store may be local to the owner agent or backed by a storage service, as long as data remains encrypted outside the decrypting agent.

## 3. Data Object Model

Each protected data object is represented as:

```yaml
record_id: "cal-2026-07-15-001"
owner_aid: "alice@mail.com:calendar_agent"
data_class: "calendar"
data_subclass: "availability"
version: 3
created_at: "2026-07-15T09:00:00Z"
updated_at: "2026-07-15T09:30:00Z"
metadata:
  time_range:
    start: "2026-07-15T10:00:00Z"
    end: "2026-07-15T11:00:00Z"
  sensitivity: "internal"
ciphertext_ref: "store://alice/calendar/cal-2026-07-15-001.ct"
encrypted_dek_ref: "store://alice/calendar/cal-2026-07-15-001.edek"
dek_alg: "AES-256-GCM"
envelope_alg: "HPKE-or-PRE-adapter"
```

Required fields:

| Field | Meaning |
|---|---|
| `record_id` | Stable identifier of the protected object |
| `owner_aid` | Owner agent identity |
| `data_class` | Coarse data type, such as calendar, mail, memory, document |
| `data_subclass` | Optional finer data type, such as availability or mail_subject |
| `version` | Data version used for revocation and freshness checks |
| `ciphertext_ref` | Location of encrypted data |
| `encrypted_dek_ref` | Location of encrypted DEK |
| `metadata` | Policy-visible metadata |

Non-goal:

- PRE-SAGA does not hide all metadata from Provider. Provider may observe access patterns, data class, requester identity, owner identity, and timing.

## 4. Cryptographic Objects

### 4.1 Data Encryption Key

Each data object has a DEK:

```text
DEK_i = random(256 bits)
```

The plaintext data is encrypted as:

```text
C_i = Enc(DEK_i, plaintext_i, aad_i)
```

Suggested AAD:

```text
aad_i = H(owner_aid || record_id || data_class || version)
```

### 4.2 Encrypted DEK

The DEK is encrypted under the owner agent's encryption key:

```text
EDEK_o_i = EncapsulateOrEncrypt(pk_o, DEK_i, context_i)
```

Context:

```text
context_i = H(owner_aid || record_id || data_class || version || dek_alg)
```

### 4.3 Re-encryption Key or Transform Context

Provider / PRE Proxy uses a transform context:

```text
RK_o_to_r_i = PREKeyGen(sk_o or delegated material, pk_r, policy_context)
```

For implementation modularity, PRE-SAGA treats this as an abstract backend interface:

```text
Transform(EDEK_o_i, rk_or_context, policy_context) -> EDEK_r_i
```

The backend may be:

- toy PRE for tests;
- HPKE/KEM wrapping adapter;
- real PRE library adapter;
- server-mediated envelope conversion baseline.

The protocol requires the interface to preserve the following boundary:

```text
Provider/PRE Proxy does not output or observe plaintext DEK_i.
```

## 5. Data Sharing Policy Schema

A Data Sharing Policy rule has the following required fields:

```yaml
policy_id: "policy-calendar-availability-v1"
owner_aid: "alice@mail.com:calendar_agent"
requester_selector:
  type: "aid_exact"
  value: "bob@mail.com:scheduler_agent"
data_scope:
  data_classes: ["calendar"]
  data_subclasses: ["availability"]
  record_selectors:
    - type: "prefix"
      value: "cal-"
purpose:
  allowed: ["schedule_meeting"]
validity:
  not_before: "2026-07-15T00:00:00Z"
  not_after: "2026-07-22T00:00:00Z"
limits:
  max_uses: 5
  max_records: 20
  allow_bulk_export: false
version_constraints:
  min_version: 1
  max_version: 3
decision:
  effect: "allow"
obligations:
  audit: true
  redact_fields: ["event_description", "participant_notes"]
```

### 5.1 Requester Selector

Supported selector types:

```yaml
requester_selector:
  type: "aid_exact" | "aid_pattern" | "owner_same_user" | "group"
  value: string
```

Examples:

```yaml
type: "aid_exact"
value: "bob@mail.com:scheduler_agent"
```

```yaml
type: "aid_pattern"
value: "*@mail.com:research_agent"
```

### 5.2 Data Scope

The policy must bind authorization to data class and data version.

```yaml
data_scope:
  data_classes: ["calendar", "mail", "memory", "document"]
  data_subclasses: ["availability", "subject", "summary"]
  record_selectors:
    - type: "exact"
      value: "doc-001"
    - type: "prefix"
      value: "cal-"
```

### 5.3 Purpose

The request must declare a purpose.

```yaml
purpose:
  allowed:
    - "schedule_meeting"
    - "expense_report"
```

The purpose is not treated as a cryptographic fact by itself. It is a policy field that must be bound into the token and audit record.

### 5.4 Validity and Usage Limits

```yaml
validity:
  not_before: "2026-07-15T00:00:00Z"
  not_after: "2026-07-16T00:00:00Z"
limits:
  max_uses: 3
  max_records: 10
```

`max_uses` limits how many PRE transform operations or decryptable EDEK retrievals may be issued under the token.

### 5.5 Data Version

```yaml
version_constraints:
  min_version: 2
  max_version: 5
```

If a record has `version = 6`, an old token bound to `max_version = 5` must fail. This supports revocation through DEK rotation and data versioning.

## 6. Data Access Request

Requester agent sends:

```yaml
request_id: "req-20260715-0001"
owner_aid: "alice@mail.com:calendar_agent"
requester_aid: "bob@mail.com:scheduler_agent"
record_query:
  data_class: "calendar"
  data_subclass: "availability"
  record_ids: ["cal-2026-07-15-001"]
purpose: "schedule_meeting"
requested_operation: "decrypt_dek"
contact_token_ref: "saga-token-or-session-id"
nonce: "base64-random"
timestamp: "2026-07-15T10:00:00Z"
requester_signature: "sig(request_fields)"
```

The request signature covers:

```text
request_id
owner_aid
requester_aid
record_query
purpose
requested_operation
contact_token_ref
nonce
timestamp
```

## 7. PRE-SAGA Data Token

If policy evaluation succeeds, Provider issues or records a data token:

```yaml
token_id: "dtok-20260715-0001"
issuer: "provider"
owner_aid: "alice@mail.com:calendar_agent"
requester_aid: "bob@mail.com:scheduler_agent"
policy_id: "policy-calendar-availability-v1"
allowed_data_classes: ["calendar"]
allowed_data_subclasses: ["availability"]
allowed_record_ids: ["cal-2026-07-15-001"]
purpose: "schedule_meeting"
not_before: "2026-07-15T10:00:00Z"
expires_at: "2026-07-15T10:10:00Z"
max_uses: 1
remaining_uses: 1
data_version_bounds:
  min_version: 3
  max_version: 3
requester_public_encryption_key_hash: "sha256(pk_r)"
owner_public_encryption_key_hash: "sha256(pk_o)"
contact_session_ref: "saga-contact-session-id"
audience: "pre-proxy"
issuer_signature: "sig(provider, token_fields)"
```

Token binding requirements:

| Binding | Purpose |
|---|---|
| `owner_aid` | Prevents cross-owner token reuse |
| `requester_aid` | Prevents requester mismatch |
| `policy_id` | Links token to the evaluated policy |
| `allowed_record_ids` | Prevents data object substitution |
| `purpose` | Prevents purpose mismatch |
| `expires_at` | Limits replay window |
| `max_uses` / `remaining_uses` | Limits repeated transforms |
| `data_version_bounds` | Supports data rotation and stale token rejection |
| `requester_public_encryption_key_hash` | Binds transformed EDEK to requester key |
| `contact_session_ref` | Connects data authorization to SAGA contact authorization |

## 8. PRE Transform Request

After token issuance, Provider / PRE Proxy performs:

```yaml
transform_request:
  token_id: "dtok-20260715-0001"
  owner_aid: "alice@mail.com:calendar_agent"
  requester_aid: "bob@mail.com:scheduler_agent"
  record_id: "cal-2026-07-15-001"
  data_class: "calendar"
  version: 3
  encrypted_dek_ref: "store://alice/calendar/cal-2026-07-15-001.edek"
  requester_public_encryption_key: "pk_r"
  timestamp: "2026-07-15T10:00:03Z"
```

Validation steps:

1. Verify token signature.
2. Verify token is not expired.
3. Verify `remaining_uses > 0`.
4. Verify requester identity matches token.
5. Verify owner identity matches token.
6. Verify record id is in allowed scope.
7. Verify data class and subclass are allowed.
8. Verify purpose matches.
9. Verify data version is within bounds.
10. Verify requester public key hash matches token.
11. Decrement `remaining_uses`.
12. Execute PRE transform.
13. Write audit record.

Output:

```yaml
transform_response:
  request_id: "req-20260715-0001"
  token_id: "dtok-20260715-0001"
  record_id: "cal-2026-07-15-001"
  transformed_encrypted_dek: "EDEK_r_i"
  ciphertext_ref: "store://alice/calendar/cal-2026-07-15-001.ct"
  data_version: 3
  audit_id: "audit-20260715-0001"
```

## 9. Protocol Flow

### 9.1 Setup

1. User registers owner and requester agents through SAGA baseline.
2. Owner agent creates local encrypted store.
3. Owner agent encrypts each data object with a fresh DEK.
4. Owner agent stores ciphertext and encrypted DEK.
5. Owner or user publishes Data Sharing Policy to Provider.

### 9.2 Contact Authorization

1. Requester agent asks SAGA Provider whether it may contact owner agent.
2. Provider evaluates owner agent's contact rulebook.
3. If allowed, SAGA OTK and access-control token flow proceeds.
4. PRE-SAGA uses the contact session as a prerequisite, not as sufficient data authorization.

### 9.3 Data Authorization and PRE Transform

1. Requester sends data access request.
2. Provider verifies contact session and requester signature.
3. Provider evaluates Data Sharing Policy.
4. Provider issues a data token or internal transform authorization.
5. Provider / PRE Proxy validates token binding.
6. Provider / PRE Proxy transforms `EDEK_o_i` into `EDEK_r_i`.
7. Requester receives ciphertext reference and transformed encrypted DEK.
8. Requester decrypts `EDEK_r_i` locally and then decrypts the ciphertext.
9. Provider writes an audit event.

## 10. Audit Log Schema

Each decision produces an audit event:

```yaml
audit_id: "audit-20260715-0001"
timestamp: "2026-07-15T10:00:03Z"
event_type: "pre_transform"
decision: "allow"
reason: "policy_match"
owner_aid: "alice@mail.com:calendar_agent"
requester_aid: "bob@mail.com:scheduler_agent"
policy_id: "policy-calendar-availability-v1"
token_id: "dtok-20260715-0001"
record_id: "cal-2026-07-15-001"
data_class: "calendar"
data_subclass: "availability"
purpose: "schedule_meeting"
data_version: 3
remaining_uses_after: 0
provider_observed_metadata:
  requester_ip_hash: "sha256(ip)"
  user_agent_hash: "sha256(client)"
crypto_boundary:
  provider_saw_plaintext_dek: false
  provider_saw_plaintext_data: false
latency_ms:
  policy_eval: 2.1
  token_validation: 0.6
  pre_transform: 4.8
```

Denied requests also produce audit events:

```yaml
decision: "deny"
reason: "purpose_mismatch"
```

Required denial reasons:

```text
contact_not_authorized
policy_not_found
requester_mismatch
data_class_denied
record_scope_denied
purpose_mismatch
token_expired
token_exhausted
version_out_of_bounds
request_signature_invalid
requester_key_mismatch
```

## 11. Revocation and Freshness

PRE-SAGA supports bounded revocation through:

- short token lifetime;
- max uses;
- data versioning;
- DEK rotation;
- policy versioning;
- audit-based detection.

PRE-SAGA does not claim immediate revocation after requester has already decrypted plaintext. Once requester obtains plaintext, technical control shifts to endpoint controls, watermarking, DLP, sandboxing, or organizational enforcement.

## 12. Implementation Interfaces

### 12.1 Policy Evaluator

```python
def evaluate_data_policy(
    policy_set,
    owner_aid: str,
    requester_aid: str,
    record_id: str,
    data_class: str,
    data_subclass: str | None,
    purpose: str,
    version: int,
    now: datetime,
) -> PolicyDecision:
    ...
```

Output:

```python
PolicyDecision(
    effect="allow" | "deny",
    policy_id="...",
    reason="...",
    max_uses=...,
    expires_at=...,
    obligations={...},
)
```

### 12.2 Token Service

```python
def issue_data_token(decision, request, requester_public_key) -> DataToken:
    ...

def validate_data_token(token, transform_request) -> TokenDecision:
    ...
```

### 12.3 PRE Proxy

```python
def transform_encrypted_dek(
    token: DataToken,
    encrypted_dek_owner: bytes,
    requester_public_key: bytes,
    context: TransformContext,
) -> bytes:
    ...
```

### 12.4 Audit Logger

```python
def write_audit_event(event: AuditEvent) -> str:
    ...
```

## 13. Acceptance Criteria for Implementation

A conforming PRE-SAGA implementation must:

1. Reject data access without prior contact authorization.
2. Reject data access when no Data Sharing Policy matches.
3. Reject requester mismatch.
4. Reject purpose mismatch.
5. Reject unauthorized data class.
6. Reject stale data versions outside token bounds.
7. Reject exhausted or expired data tokens.
8. Produce an audit event for both allow and deny decisions.
9. Ensure Provider / PRE Proxy does not output plaintext DEK.
10. Ensure Provider / PRE Proxy does not output plaintext data.
11. Bind transformed encrypted DEK to requester public key.
12. Bind authorization to owner, requester, record id, data class, purpose, version, expiry, and max uses.

## 14. Protocol Non-Goals

PRE-SAGA does not claim to:

- invent a new PRE cryptographic primitive;
- hide all access metadata from Provider;
- prevent a legitimate requester from leaking plaintext after decryption;
- solve compromised endpoint security;
- provide immediate revocation of already decrypted data;
- replace SAGA contact authorization;
- prove implementation-level memory safety;
- provide full traffic analysis resistance.

These limits must be explicitly stated in the paper to avoid overclaiming.
