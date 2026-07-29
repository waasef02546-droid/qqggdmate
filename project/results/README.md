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
as current REL-001 evidence.

The `provider_plaintext_probe` row is an intentional limitation result: it
demonstrates that ToyPRE permits public-material DEK recovery. The `False`
plaintext-visibility fields in other tables are instrumentation observations,
not proof of cryptographic Provider confidentiality.
