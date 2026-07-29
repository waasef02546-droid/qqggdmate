@echo off
setlocal
set "SEMGREP_SEND_METRICS=off"
"%~dp0.venv\Scripts\semgrep.exe" mcp
