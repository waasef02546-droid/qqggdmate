# Archive staging area

This directory is reserved for hash-verified, recoverable legacy material.

The first hash-verified migration was completed on 2026-07-28. Before any later archive operation:

1. inspect all code, paper, and script references;
2. record the source tree hash in `docs/repository/archive-manifest.yaml`;
3. update references in the same bounded work package;
4. move only explicitly approved paths;
5. verify the destination hash and keep the Git history recoverable.

The coupled legacy prototype set is now stored as:

- `archive/legacy-prototype/prototype/`
- `archive/legacy-prototype/configs/`
- `archive/legacy-prototype/results/experiment_summary.csv`

They moved together because they represent one historical implementation/schema/result chain.
The move record and rollback mapping are in
`docs/repository/layout-migration-2026-07-28.md`.
