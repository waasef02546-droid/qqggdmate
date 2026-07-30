# CRYPTO-001 acceptance review

- Review date: `2026-07-31`
- Decision: `accepted` within the documented prototype boundary
- Release input commits: initial backend `9d4b99812b971f04e4fa0baf8790e999d3fd1557`;
  final binding/evidence audit correction `7c27e7ce8f01922dd5c75190fcdb2d1c57e391c7`;
  bounded evidence wording `95061e6c1f8d9f04d182475dc365bb8b24575a36`
- Accepted run: `20260730T193022Z-41303f6f`
- Source fingerprint:
  `0fd338a39d5ec2ec6ee4ecd376309412f5c13cfc0e434c0b88bd790a3001316e`
- Independent verifier: `PASS`

## Acceptance summary

| Gate | Result | Evidence |
|---|---:|---|
| Concrete PRE implementation | pass | `UmbralPREBackend` uses `MessageKit`, signed and fully verified KFrags, proxy CFrags, and requester-side verified decrypt |
| Versioned/fail-closed artifacts | pass | suite/version/kind/length/context/owner/requester binding; malformed, wrong-key, wrong-context, truncation, and tamper tests |
| Provider binding and failure order | pass | active owner and requester registration keys are trusted transform inputs; wrapper owner-key substitution and crypto failures are denied/audited before one-use token consumption |
| Publication path migration | pass | service default, attacks, tasks, SAGA bridge, Mongo E2E, and performance use `UmbralPREBackend`; structural guard rejects Toy/HPKE constructors |
| Malicious data-plane Provider regression | pass | registrations, policies, tokens, encrypted objects, complete audit metadata, and PRE artifacts contain no raw/base64/hex DEK; public-key unwrap misuse fails and intended requester decrypt succeeds |
| Historical ToyPRE defect | pass | public-material DEK recovery remains a labelled unit regression only |
| Trusted rotation compatibility | pass | concrete decrypt-and-fresh-encrypt rewrap and JSON/Mongo lifecycle tests pass |
| Focused verification | pass | backend, Provider, storage, registration, rotation, attack, task, performance, bridge, traceability, and verifier checks |
| Full regression | pass | 101/101 with live MongoDB 8.3.4, no skips |
| Authoritative release | pass | all nine gates pass; 23 artifacts bound to 138 source files |
| Independent release verification | pass | `python scripts/verify_release.py` |

## Release gate detail

- Blocking attacks: `8/8`.
- Active ToyPRE limitation paths: `0`.
- Concrete Provider recovery gate: the exposed-state regression found no DEK, public-key unwrap
  misuse was rejected, and requester decrypt succeeded.
- Tool tasks: `4/4`.
- Performance rows: `12/12`; all three full Provider rows link to the separately evaluated
  Provider recovery gate and do not claim that latency measurement establishes confidentiality.
- ProVerif: `3/3` models, `4` true queries.
- SAGA evidence bridge: `2/2`.
- Live Mongo E2E: passed.
- Release inputs: clean relative to the declared 138-file source set.
- Other workspace materials remained present but outside the release-input set and were not
  staged into the input commit.

## Failures and corrections retained

1. The first 25-test focused run found that rotation candidates recomputed their public-key
   fingerprint with the old generic algorithm domain and that one HTTP test expected that generic
   label. The registry now preserves the active algorithm domain during replacement; the HTTP
   expectation now names the explicitly injected HPKE fixture. The five nearest tests then passed.
2. A 62-test focused run found one traceability guard still matching the old T2 heading. The guard
   was updated to the data-plane-specific claim and all four traceability checks passed.
3. The first Mongo attempt incorrectly passed an unquoted data path to `mongod`; all five Mongo
   tests skipped and were rejected as evidence. A new isolated, quoted data directory was started,
   the server reported MongoDB 8.3.4, and the same five tests passed with no skips.
4. Release preflight `20260730T190452Z-b76cb299` passed every scientific gate and was rejected only
   by the intended dirty-input gate. Run `20260730T190920Z-390efd0b` then passed from commit
   `9d4b998`.
5. Updating the source-fingerprinted claims matrix from pending to accepted correctly invalidated
   that first manifest. The final claims were made non-self-referential, committed at `567e79a`,
   and a superseding run passed all gates.
6. Final read-only audit then found the paper still described the old REL-001 dirty/128-file
   source state. The paper now defers exact HEAD/count/fingerprint to its same manifest, commit
   `99c3b1b` records that correction.
7. The final acceptance audit found five remaining semantic gaps: the protocol described token
   consumption before crypto validation; it claimed an unimplemented requester signature; the
   Provider probe omitted service-state/audit snapshots and overstated its boundary; performance
   rows self-asserted confidentiality; and the wrapper owner key was not directly compared with
   the active owner registration. Commit `7c27e7c` closes all five, including an adversarial
   wrapper-substitution test that preserves valid provenance and confirms no token consumption.
8. Commit `95061e6` narrows the manifest language to the exact exposed-state/public-API regression.
   Final run `20260730T193022Z-41303f6f` passed all nine gates and independent verification.

## Claim boundary

Acceptance supports only this bounded statement:

> In the tested single-Provider data plane, the concrete Umbral adapter transforms an
> owner-encrypted DEK with public artifacts and signed delegation material without either private
> key. In the bounded exposed-state/public-API regression, no raw/base64/hex DEK appears, direct
> public-key unwrap misuse fails, and the registered requester decrypts.

Acceptance does not establish:

- production security or an independent audit of `nucypher-core==0.15.0` or the adapter;
- side-channel, memory-compromise, secure-zeroization, or supply-chain guarantees;
- HSM/KMS custody or confidentiality after compromise of the trusted management plane;
- Provider/requester collusion resistance for retained owner/requester key-pair-scoped KFrags;
- cryptographic erasure of copied rekeys or automatic migration of ToyPRE/HPKE artifacts;
- equivalence between the ProVerif abstraction and the concrete Rust/Python implementation;
- multi-Provider linearizability, RAFT, sharding, or Mongo multi-document transactions.

The dependency is Alpha and GPLv3. Redistribution and repository licensing require separate legal
and release review.

## Residual priority

The smallest high-value follow-up is not another backend replacement. It is a bounded key-custody
package that moves rotation decrypt-and-fresh-encrypt to an owner/KMS boundary and decides whether
per-record delegating keys or a label-bound PRE construction will address retained KFrag scope.
That package is not started by this acceptance.
