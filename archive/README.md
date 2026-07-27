# Archive staging area

This directory is reserved for hash-verified, recoverable legacy material.

Nothing is moved here automatically. Before any archive operation:

1. inspect all code, paper, and script references;
2. record the source tree hash in `docs/repository/archive-manifest.yaml`;
3. update references in the same bounded work package;
4. move only explicitly approved paths;
5. verify the destination hash and keep the Git history recoverable.

The first candidate is the coupled legacy prototype set:

- `prototype/`
- root `configs/`
- `results/experiment_summary.csv`

These must move together because they represent one historical implementation/schema/result chain.
