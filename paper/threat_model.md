# PRE-SAGA Threat Model and Security Goals

## 1. System Setting

PRE-SAGA considers a multi-agent system where autonomous or semi-autonomous agents communicate, request delegated access, and operate on local data such as calendar entries, mail, documents, memory records, and tool outputs.

SAGA provides the contact layer:

```text
Can requester agent contact owner agent?
```

PRE-SAGA adds the data layer:

```text
Can requester agent decrypt a specific data object for a specific purpose under a bounded policy?
```

## 2. Protected Assets

The system protects:

- plaintext data records;
- plaintext data encryption keys;
- owner agent private keys;
- requester agent private keys;
- integrity of Data Sharing Policy decisions;
- binding between token, requester, owner, purpose, data class, record id, and data version;
- auditability of data-sharing events.

## 3. Trust Assumptions

### 3.1 Trusted Components

The following are trusted for the stated properties:

- cryptographic libraries correctly implement encryption, signature, hashing, and PRE or KEM operations;
- owner agent correctly encrypts data before storage;
- requester agent private key is not leaked before authorization;
- owner agent private key or delegated PRE material is protected according to the selected backend;
- Provider / PRE Proxy executes the published policy evaluation code as specified.

### 3.2 Honest-but-Curious Provider Variant

The primary design target is an honest-but-curious Provider / PRE Proxy:

- follows the protocol;
- may inspect all metadata it receives;
- may attempt to infer sensitive relations from metadata;
- must not learn plaintext data or plaintext DEK.

### 3.3 Malicious Requester Variant

The requester may:

- request unauthorized data classes;
- lie about purpose;
- reuse tokens;
- use another requester's token;
- request stale data versions;
- attempt to replay previous transform requests;
- attempt to decrypt data outside policy scope.

### 3.4 Malicious External Attacker

An external attacker may:

- observe network traffic;
- replay old messages;
- tamper with requests;
- submit forged requests without valid agent credentials;
- attempt to use stolen token material without the corresponding requester key.

The attacker is not assumed to break standard cryptographic primitives.

## 4. In-Scope Threats

### T1: Unauthorized Data Class

Requester is allowed to contact owner agent but asks for a data class not authorized by Data Sharing Policy.

Expected outcome:

```text
deny: data_class_denied
```

### T2: Purpose Mismatch

Requester uses a token or request intended for `schedule_meeting` to access data for `expense_report`.

Expected outcome:

```text
deny: purpose_mismatch
```

### T3: Requester Mismatch

Agent C attempts to use a token issued to Agent B.

Expected outcome:

```text
deny: requester_mismatch or requester_key_mismatch
```

### T4: Token Reuse

Requester tries to use a data token after `max_uses` reaches zero.

Expected outcome:

```text
deny: token_exhausted
```

### T5: Token Replay After Expiry

Requester replays an old transform request after token expiration.

Expected outcome:

```text
deny: token_expired
```

### T6: Stale Rekey / Version Mismatch

Requester attempts to use an authorization bound to an old data version after DEK rotation.

Expected outcome:

```text
deny: version_out_of_bounds
```

### T7: Provider Plaintext Probe

Provider / PRE Proxy attempts to recover plaintext DEK or plaintext data during transform.

Expected outcome:

```text
provider_saw_plaintext_dek = false
provider_saw_plaintext_data = false
```

### T8: Policy Bypass by Record Substitution

Requester obtains authorization for one record and substitutes another record id during transform.

Expected outcome:

```text
deny: record_scope_denied
```

## 5. Out-of-Scope Threats

PRE-SAGA does not fully solve:

- requester leaking plaintext after legitimate decryption;
- malware on requester or owner endpoint;
- side channels inside cryptographic implementations;
- full metadata privacy against Provider;
- traffic analysis by a network-level observer;
- denial-of-service against Provider or storage;
- social engineering attacks on users;
- policy authoring mistakes by the data owner;
- legal or organizational enforcement after plaintext export.

These limitations should be stated directly in the paper.

## 6. Security Goals

### G1: DEK Secrecy Against Provider

Provider / PRE Proxy must not learn plaintext DEK while performing authorization and transform.

Informal property:

```text
Provider observes EDEK_o_i and EDEK_r_i, but not DEK_i.
```

### G2: Data Confidentiality Before Authorized Decryption

No requester can decrypt a data object unless:

- contact authorization is valid;
- Data Sharing Policy allows the request;
- data token is valid;
- PRE transform is bound to requester key;
- record id, class, purpose, and version match.

### G3: Requester Binding

A data token issued to `A_r` cannot be used by `A_x`.

Required binding fields:

```text
requester_aid
requester_public_encryption_key_hash
token_id
issuer_signature
```

### G4: Owner and Record Binding

A token issued for owner `A_o` and record `D_i` cannot be reused for owner `A_o'` or record `D_j`.

Required binding fields:

```text
owner_aid
record_id
data_class
data_subclass
version
```

### G5: Purpose Binding

A token issued for one purpose cannot authorize a different purpose.

Required binding field:

```text
purpose
```

### G6: Bounded Use

Authorization must be bounded by:

- expiry;
- max uses;
- version constraints;
- policy id.

### G7: Policy Compliance

Provider / PRE Proxy must only transform encrypted DEKs if a Data Sharing Policy rule evaluates to allow.

### G8: Auditability

Every allow or deny decision must produce an audit record containing:

- decision;
- reason;
- requester;
- owner;
- record id;
- data class;
- purpose;
- policy id;
- token id;
- timestamp.

## 7. Security Non-Goals

PRE-SAGA does not claim:

- complete privacy from Provider metadata observation;
- prevention of plaintext leakage by an authorized requester;
- replacement of endpoint security;
- instant revocation after requester has decrypted data;
- protection against broken cryptographic libraries;
- protection against malicious policy authors;
- full anonymity of agents.

## 8. Adversary Capabilities Matrix

| Capability | External attacker | Malicious requester | Honest-but-curious Provider |
|---|---:|---:|---:|
| Observe metadata | partial | partial | yes |
| Read ciphertext | possible | possible | possible |
| Read plaintext DEK | no | only after valid decrypt | no |
| Forge owner signature | no | no | no |
| Reuse token | possible | yes | possible |
| Change purpose field | possible | yes | possible |
| Substitute record id | possible | yes | possible |
| Bypass policy evaluator | no | no | no under HBC assumption |
| Infer access pattern | possible | possible | yes |

## 9. Required Tests Derived from Threat Model

| Test | Expected result |
|---|---|
| normal authorized sharing | allow |
| unauthorized data class | deny |
| purpose mismatch | deny |
| token reuse after max uses | deny |
| requester mismatch | deny |
| expired token | deny |
| stale data version | deny |
| provider plaintext probe | no plaintext DEK/data exposed |
| audit log completeness | audit event exists for allow and deny |

## 10. Paper-Level Boundary Statement

PRE-SAGA should be presented as a data-sharing governance extension to SAGA, not as a complete solution to all agent data leakage. Its central claim is narrower:

> PRE-SAGA reduces unnecessary plaintext exposure at the Provider and adds enforceable, auditable data-object-level authorization after SAGA contact authorization.

This claim is testable through policy denial experiments, requester binding experiments, token reuse experiments, and Provider plaintext boundary tests.
