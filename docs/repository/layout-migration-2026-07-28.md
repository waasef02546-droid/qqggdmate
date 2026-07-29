# Layout migration record — 2026-07-28

## Purpose

This migration separates the current PRE-SAGA implementation from legacy prototypes, historical
evidence, research reviews, and machine-local state. It improves search precision and makes
`project/` the single authoritative engineering entry point without deleting user material.

The operation changed paths only. It did not change PRE-SAGA behavior, experiment conclusions, or
paper claims.

## Completed moves

| Before | After | Files | Bytes |
|---|---|---:|---:|
| `comparison_reports/` | `docs/reviews/saga/` | 2 | 21,720 |
| `project/result/` | `project/results/legacy/stage2/` | 5 | 61,059 |
| `prototype/` | `archive/legacy-prototype/prototype/` | 3 | 15,578 |
| `configs/` | `archive/legacy-prototype/configs/` | 1 | 5,060 |
| `results/experiment_summary.csv` | `archive/legacy-prototype/results/experiment_summary.csv` | 1 | 211 |

## Integrity evidence

Directories use SHA-256 over sorted `relative_path|file_sha256` records joined with LF. Because
the repository-relative path changes during a move, both the original and current manifest hash
are retained. `content_tree_sha256` removes the moved directory prefix and therefore proves that
the contained names and bytes did not change.

| Current path | Original manifest SHA-256 | Final manifest SHA-256 | Move-verified content-tree SHA-256 |
|---|---|---|---|
| `docs/reviews/saga/` | `7c4cbe6feab44a3878c52103ce05704e91af971d80b9a96d17aad26688e98e34` | `0b667df0c9202cf607ec824590b3f25746781a02e56851738da7c3a68e4ec1e0` | `dff4ba419022b5e0fa8f081cf73f4c9161e4add0b0683a25b8240f3459ef13a9` |
| `project/results/legacy/stage2/` | `f544eb21a9e9537212fd14c377bce70c0fd7bd8468ce32d6a1a3e63f01f1786e` | `a4530048dd3e0fd4f4806e9d61c20b150775faf4850e9867ad8ce8c1588d0dac` | `87ee64a554c56606ccdb8e1ddf393ca8d6cd2d4028024957896a6c5d09049a60` |
| `archive/legacy-prototype/prototype/` | `1efe103e3d062122ef8b5384ff76ef97263d6ff89e36973f3b953313278cb616` | `a0fab48feed56b724adc68a798fb7c782c980410099ad6dbb723126ce5e3952e` | `3e372654afa967a918ff5daf5c80c5e884f7ed475cd0eb3e88f1dce094794732` |
| `archive/legacy-prototype/configs/` | `5757e5c0ad513b35ad41de4096e6eeb357d833aa8401335486cdaef052c019f9` | `8e14bab30fa18a2b8684334ad9eff49668f4e354765d62e0d9a04ff25b3391a2` | `fd7a2ee949735b5578bb4e31ab2b00e36c726d374d336aed8a621611396ee3e2` |
| `archive/legacy-prototype/results/experiment_summary.csv` | `15359589910b708b3d6c27564d2de9b86bd2faa7bb0446a30139da20f1836b14` | `15359589910b708b3d6c27564d2de9b86bd2faa7bb0446a30139da20f1836b14` | `15359589910b708b3d6c27564d2de9b86bd2faa7bb0446a30139da20f1836b14` |

File counts and byte totals were checked before and after every move and remained equal. After
that check, two moved Markdown files were intentionally edited to point at their new locations;
the final manifest hashes in `archive-manifest.yaml` therefore differ from the move-time hashes,
while the separately retained move-verified hashes prove the filesystem operation itself was
lossless.

## Reference updates

Repository entry-point documentation, ignore rules, Serena exclusions, paper planning references,
legacy runner instructions, Stage-2 self-references, and baseline review links were updated to the
new locations. No compatibility junctions or duplicate copies were created.

## Material intentionally not moved

`Record/`, `results/compare/`, `saga_reproduction/`, `runtime/`, `tools/`, `tmp/`, and private
reference inputs remain at their previous paths. Their blockers are recorded in
`archive-manifest.yaml`.

## Recovery procedure

The migration is reversible while the former paths remain absent:

1. stop any process reading or writing the five current paths;
2. verify each former path is absent and each current path still matches the recorded hash;
3. move each current path back to its exact former path using one filesystem operation;
4. reverse the reference updates; and
5. rerun the repository hygiene and workflow checks.

Do not merge the current and former directories or overwrite an existing rollback target. If any
hash differs, stop and inventory the changed files before recovery.

## Verification scope

No functional or experiment suite was rerun because current implementation and configuration did
not change. Only path integrity, obsolete-reference search, repository hygiene, and workflow
control checks are required for this migration.
