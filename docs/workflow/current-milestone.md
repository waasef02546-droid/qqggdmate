# Current milestone

## Active work package

- ID: `CFG-002`
- Title: Repository normalization, readable guidance, and active-tool alignment
- State: `accepted`
- Authorization date: `2026-07-28`
- Acceptance date: `2026-07-28`
- Objective: make the existing repository control plane human-readable and operationally
  unambiguous by repairing document encoding, reconciling active MCP configuration, defining one
  authoritative engineering tree, recording a recoverable legacy-archive plan, and establishing a
  reviewable Git baseline.
- Authorized scope: repository guidance and configuration, MCP/Skill inventory, encoding-only
  document repairs, directory ownership maps, archive manifests, `.gitignore`, Git status
  classification, control checks, and evidence updates.
- Non-goals: changing PRE-SAGA protocol or cryptographic behavior, changing experiment results,
  strengthening paper claims, deleting or irreversibly moving historical material, committing or
  pushing without explicit user authorization, or starting `CORE-002`.

## Selected orchestration mode

- Mode: `A`
- Rule: the primary agent owns integration; independent read-only agents may audit MCP loading and
  directory references. No parallel writes to repository files.

## Acceptance criteria

- `AGENTS.md`, `agens.txt`, the root README, and the experiment-tracking entry point are valid,
  readable UTF-8 without changing research meaning.
- A checked-in inventory distinguishes installed Skills, Plugins, configured MCP servers, and
  runtime-visible MCP servers, including the reason for any mismatch.
- `project/` is documented as the only authoritative PRE-SAGA engineering tree.
- Every major root-level legacy, generated, reproduction, external, and temporary directory has an
  owner classification and a non-destructive migration or archive disposition.
- `.gitignore` and a Git-baseline report distinguish source/evidence from caches, temporary files,
  generated results, and historical user material without discarding existing files.
- No PRE-SAGA core behavior or experiment result is changed.
- Repository control validation and document/link checks pass and are recorded in the test ledger.

## Evidence obligations

- Preserve before/after encoding evidence and list files that cannot be losslessly recovered.
- Record the active config paths and exact MCP/Skill inventory commands.
- Record directory-reference evidence before proposing any move.
- Treat existing dirty and untracked files as user material; do not stage, commit, delete, or move
  them automatically.

## Verification evidence

- Strict repository hygiene validation passed for 304 governed UTF-8 text files; no invalid UTF-8
  or replacement characters were found.
- Seven planned/held legacy sets have stable recorded file counts, byte counts, and SHA-256
  manifests; no historical file was moved or deleted.
- User-level `CODEX_HOME=C:\Users\asus\.codex` was persisted. With that config root, both installed
  CLI versions list `node_repl` and `openaideveloperdocs`.
- The repository control checker passes with 24 required files and the YAML evidence files parse.
- The accepted CORE-001 implementation is isolated in Git commit `9966bab`; CFG-002 control/layout
  files are isolated from paper drafts, result artifacts, reproduction material, and unknown user
  files.
- PRE-SAGA functional tests were not rerun because CFG-002 did not change core behavior and the
  equivalent CORE-001 verification remains valid.

## Risks

- Mojibake containing replacement characters may not be mechanically reversible and may require
  reconstruction from an earlier source.
- Different Codex binaries or environment variables may resolve different configuration roots.
- Physical directory moves can break paper links, imports, or experiment provenance; CFG-002 will
  produce a recoverable plan and only perform moves proven safe and explicitly in scope.
- A clean Git baseline may require a later user-approved commit because the current worktree
  contains substantial pre-existing changes.
- Physical legacy moves remain plan-only. `results/compare/*.png` and `paper/方案.zip` have unknown
  provenance and remain untouched.

## Previous accepted work package

- `CORE-001`: accepted on `2026-07-26`; server-enforced Contact-to-data-token-to-re-encryption
  binding implemented and verified.

## Proposed next work package

- Candidate: `CORE-002`
- Topic: authenticated AID-to-registered-key binding and trusted management/data-plane separation.
- State: `not_authorized`
- Rule: do not implement it during `CFG-002`.
