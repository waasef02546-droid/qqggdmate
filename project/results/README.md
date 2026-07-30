# Result authority

`release-manifest.json` defines the current accepted result set. It records the
source fingerprint, configuration hash, environment, acceptance gates, and the
hash and row count of each authoritative artifact.

Verify it from `project/`:

```powershell
python scripts/verify_release.py
```

Files listed in the manifest belong to the run identified inside that
manifest. Files not listed are historical or auxiliary and must not be cited
as current CRYPTO-001 evidence.

The authoritative backend is `umbral-pre-v1` over
`nucypher-core==0.15.0`. The `provider_plaintext_probe` row is an
expected-blocked exposed-state/public-API regression: it snapshots Provider
registrations, policies, tokens, encrypted objects, audit metadata, and PRE
artifacts; checks for raw/base64/hex DEK leakage and direct public-key unwrap
misuse; and separately requires the intended requester to decrypt.

This is prototype-bounded empirical evidence, not cryptanalysis, memory
forensics, a cryptographic proof, independent audit, side-channel claim, or
guarantee for the trusted management plane. ToyPRE public-material recovery
remains a unit-level defect characterization and is not an authoritative
release path.
