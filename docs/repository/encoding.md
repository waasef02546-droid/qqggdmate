# Text encoding policy

- Canonical encoding: UTF-8
- Canonical line ending: LF, except PowerShell scripts use CRLF
- Enforcement: `.editorconfig` and `.gitattributes`

## Audit result

On `2026-07-28`, the final CFG-002 hygiene checker strictly decoded 304 governed
text/config/source files as UTF-8, excluding downloaded tools, local runtime state, Git internals,
and Python caches.

- Invalid UTF-8 files: 0
- Files containing Unicode replacement character `U+FFFD`: 0

`agens.txt`, `README.md`, `EXPERIMENT_TRACKING.md`, and `AGENTS.md` were not corrupt. The earlier
mojibake came from Windows PowerShell reading UTF-8 through its default local code page.

Use:

```powershell
Get-Content -Encoding UTF8 .\agens.txt
```

Do not run a GBK-to-UTF-8 conversion on these files; that would corrupt valid text.
