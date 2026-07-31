# ADR 0009: authenticated owner-side rewrap custody

- Status: accepted for `KEYCUSTODY-001`
- Date: 2026-07-31

## Context

The previous rotation endpoint accepted an owner's source private key. Although that path was
called a trusted management plane, it was co-located with the Provider service and performed
decrypt-and-fresh-encrypt inside the Provider call graph. This contradicted the useful operational
boundary that the Provider should hold public registration state, ciphertext, and PRE artifacts,
but not owner private keys or plaintext DEKs.

This decision addresses custody during owner-key rotation only. It does not change the data-plane
Umbral transformation, and it does not narrow the owner/requester key-pair scope of retained
KFrags.

## Decision

The Provider exports a schema-version-1 `OwnerRewrapRequest` reconstructed from live registry,
rotation-journal, encrypted-object, and object-revision state. Its canonical digest binds:

- backend, rotation ID, owner AID, store ID, record ID, and expected object revision;
- source and target registration IDs, versions, public-key fingerprints, and public keys;
- a digest of the authoritative source owner wrapper; and
- digests of the source and target owner-wrap contexts.

The request contains no private key or plaintext DEK. An owner/KMS-side custodian first requires a
separate owner-controlled approval that exactly names the rotation, store, record, revision,
source registration, target registration, target fingerprint/key, and complete request digest.
It rejects a request whose record or target was substituted. The custodian then verifies the
source private key against the request's authoritative source public key, validates the source
wrapper, decrypts and freshly encrypts the DEK locally, validates the target wrapper, and signs a
domain-separated message containing the request digest and target-wrapper digest. The artifact
contains the request digest, encrypted target wrapper, signature, and versioned custody metadata.

The Provider reconstructs the request instead of trusting caller-supplied binding fields. It
verifies the artifact with the source public key from the active source registration, validates
the target Umbral envelope for the exact target key and context, and only then executes the
existing object-revision compare-and-swap. The artifact cannot nominate its own verification key.

An exact valid artifact retry is idempotent. A different valid artifact for the same
rotation/object is rejected as `custody_artifact_conflict`; stale, malformed, cross-record,
cross-rotation, or forged artifacts fail before mutation. The legacy `source_private_key_b64`
field is rejected and has no fallback.

## Key-use and trust boundary

The prototype uses the source Umbral secret key to produce the domain-separated custody
attestation because the current registration schema has no separate KMS signing key. This proves
possession relative to the registered source key in the tested prototype, but it is not the
preferred production key separation. A deployment-grade design should register a dedicated KMS
attestation key, protect it in an HSM/KMS, authenticate the Provider-to-KMS channel, and define
authorization/audit policy inside that service.

The prototype CLI treats the approval JSON as a trusted owner-local input. It does not sign that
file, authenticate its operating-system provenance, or stop a compromised owner host from
replacing both request and approval. The established result is therefore that the custodian
requires and exactly compares an explicit local approval; it is not remote approval attestation.

The custodian still materializes the source private key and plaintext DEK in its own memory. This
decision removes those values from Provider APIs and Provider-owned state; it does not establish
secure-memory zeroization, remote attestation, side-channel resistance, or a whole-process
malicious-Provider theorem.

## Persistence, recovery, and compatibility

Only encrypted wrappers and the 32-byte custody request digest are added to stored owner-wrap
state. JSON and Mongo readers accept older wraps with no custody digest. New staging requires a
signed version-1 artifact; an in-progress rotation created by the removed private-key API must be
aborted and prepared again. Prepared requests are deterministic for the same authoritative state.
If the custodian succeeds but the response is lost, the artifact may be safely resent; if staging
was persisted before the reply was lost, the exact retry returns the already-staged object.

Multi-object rotation remains a recoverable sequence over per-object CAS plus a rotation journal,
not a cross-document transaction. Mongo aggregate and encrypted-object CAS remain distinct
atomicity domains.

## KFrag scope decision

`nucypher-core==0.15.0` provides key-pair-scoped Umbral KFrags, not native record-label-bound PRE.
The selected follow-up direction is owner/KMS-held, label-derived, per-record-version delegating
keys, with migration and direct retained-KFrag attack evidence in a separate `KFRAGSCOPE-001`
work package. Until implemented, PRE-SAGA continues to state that Provider/requester collusion can
reuse a copied KFrag across compatible capsules under the same owner/requester key pair.

## Consequences

- Provider rotation interfaces no longer accept owner private keys or invoke decrypt-and-rewrap.
- Owner-side tooling or a KMS client becomes a required rotation participant.
- Artifact authentication, canonical binding, replay behavior, and object CAS are independently
  testable and release-gated.
- The narrower custody claim is stronger and more falsifiable, while retained-KFrag and
  co-located-process limitations remain explicit.
