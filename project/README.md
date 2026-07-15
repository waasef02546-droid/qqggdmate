# PRE-SAGA Prototype

This directory contains the stage 2 PRE-SAGA prototype implementation.

The prototype implements the minimum runnable framework required by `paper/plan.md`:

- policy evaluator
- token service
- encrypted store
- toy PRE interface
- audit logging
- unit and integration tests

The cryptographic backend is intentionally marked as `toy_pre`. It is used to validate protocol behavior and test bindings, not for production security.

## Run tests

```powershell
cd project
python -m unittest discover -s tests -v
```

## Expected result

All tests should pass. The tests cover:

- allowed data sharing
- data class denial
- purpose mismatch
- requester mismatch
- data version mismatch
- token max-use exhaustion
- encrypted store round trip
- PRE transform without Provider plaintext DEK exposure
