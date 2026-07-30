# ADR 0008: Concrete Umbral PRE backend and bounded confidentiality claim

- Status: accepted for implementation
- Date: 2026-07-31
- Work package: `CRYPTO-001`

## Context

The accepted `REL-001` release demonstrated that `ToyPRE` allows anyone holding the owner public
key, owner-wrap context, and wrapped DEK to recover the DEK. `HPKEKEMStub` has the same control-flow
purpose and is not an HPKE implementation. Neither can support a concrete Provider-confidentiality
claim.

The PRE-SAGA sharing path needs a construction in which:

1. the owner encrypts a DEK;
2. only the owner can create owner-to-requester delegation material;
3. the Provider can transform the encrypted DEK without an owner or requester secret; and
4. only the intended requester can recover the DEK from the transformed artifact.

An X25519/HKDF/AEAD recipient-wrap composition would be useful key sharing, but it would not be
proxy re-encryption. It is therefore rejected for this work package.

## Decision

Use `nucypher-core==0.15.0` as the exact dependency for a research-grade
`UmbralPREBackend`. The adapter uses the package's canonical Umbral operations:

- `MessageKit` for encryption under the owner's Umbral public key;
- a fresh signing key and signed 1-of-1 `KeyFrag` for owner-to-requester delegation;
- full `KeyFrag.verify` checks against the signing, delegating, and receiving public keys;
- `reencrypt` to create a capsule fragment without either private key;
- full capsule-fragment verification before `decrypt_reencrypted`.

The adapter owns versioned binary envelopes for owner wraps, rekeys, and transformed artifacts.
Each envelope has an unambiguous magic value, adapter version, object kind, suite identity, exact
lengths, canonical public-key encodings, and a SHA-256 digest of the PRE-SAGA owner-wrap context.
Unknown, legacy, malformed, truncated, substituted, or trailing data fails closed.

The exposed Umbral `MessageKit` API does not expose application AAD. The adapter therefore embeds
an application-domain marker, adapter version, exact context digest, owner public key, and 32-byte
DEK inside the encrypted payload. The requester checks this payload after cryptographic
decryption. Outer context and key fields let the Provider reject mismatched delegation before
token consumption; the encrypted copy prevents an altered outer header from being accepted by the
recipient.

The Provider precomputes and cryptographically validates a transform before the atomic one-use
token consume. If validation fails, it emits a stable denial audit and returns no transformed
material. If a concurrent request wins consumption, the losing precomputed fragment is discarded.

`rewrap_dek` is not called proxy re-encryption. It is a trusted-management operation that decrypts
the old owner wrap and freshly encrypts the DEK for a candidate owner key. A future package must
move that operation to an owner-side client or isolated KMS/HSM before a whole-process malicious
Provider claim is possible.

## Threat and claim boundary

The concrete acceptance gate is deliberately narrow:

- the probe snapshots the data-plane Provider's registered public material, policy/token state,
  encrypted objects, complete audit metadata, context, delegation material, and transformed
  result;
- without either private key, the snapshot must contain no raw/base64/hex DEK and direct use of a
  public key with the exposed unwrap API must fail;
- the registered requester must decrypt the same transformed result successfully.

This is an exposed-state/public-API regression and prototype-bounded evidence. It is not
cryptanalysis, memory forensics, a reduction, an independent audit, a side-channel claim, or
production assurance.

Umbral KFrags are scoped to a delegating/receiving key pair, not to a PRE-SAGA record, purpose, or
token. The adapter binds a context in its envelopes and plaintext checks, so the normal Provider
path rejects cross-context substitution. A malicious Provider colluding with the intended
requester could retain a valid KFrag and apply it directly to another capsule under the same owner
key. This limitation remains explicit. Per-record delegating keys or a label-bound PRE
construction would be required to remove it.

## Key custody and lifecycle

- Agent encryption private keys and rekey generation remain owner-side in the sharing flow.
- The Provider stores public keys, owner ciphertexts, signed KFrags, and CFrags only.
- The current trusted management plane can receive a source private key for staged rotation.
  Logical management/data-plane separation does not protect against compromise of a co-located
  trusted management process.
- Python byte objects and the Rust extension provide no repository-evidenced secure-memory
  zeroization guarantee.
- Old KFrags can be copied before revocation. Registration version checks stop normal-path reuse
  but cannot erase adversarial copies.

## Compatibility and migration

ToyPRE and HPKE-stub key material and ciphertexts are incompatible with Umbral. The new adapter
must never infer a legacy format from length or try to reinterpret it. Legacy artifacts fail
closed.

Migration requires a trusted holder of each legacy owner secret to decrypt each old DEK and create
a fresh Umbral owner wrap. Existing prepare/stage/CAS/commit recovery mechanics can coordinate
such a migration, but automatic legacy migration is outside `CRYPTO-001`.

## Dependency and supply-chain boundary

The exact selected package is `nucypher-core==0.15.0`. The reviewed CPython 3.12 Windows wheel has
SHA-256:

`172b7b9a82c73b4c3c75719c32a84cf2c592789418ebdfb8ee3eba8699a021f9`

The official package metadata identifies the release as Alpha and the license as GPLv3. The
repository has not independently audited the Rust implementation, reproduced the wheel build, or
obtained legal advice about redistribution. GPL compliance and repository licensing must be
resolved before distributing a combined application or wheel.

Primary upstream references:

- <https://pypi.org/project/nucypher-core/0.15.0/>
- <https://github.com/nucypher/nucypher-core>

## Consequences

- Publication-facing code gains an actual Umbral proxy transform instead of an XOR mask.
- Ciphertexts and delegation artifacts become larger and parsing/authentication can fail.
- Provider error handling and token-consumption order must change.
- Performance evidence must be regenerated and must identify the backend and exact version.
- The ToyPRE recovery probe remains as a defect regression, while the active release probe inverts
  to require failed Provider recovery plus successful requester decryption.
- Formal evidence remains an abstraction and cannot certify the concrete dependency or adapter.
