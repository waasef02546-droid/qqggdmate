@echo off
setlocal
set "SERENA_HOME=%~dp0state"
set "SERENA_USAGE_REPORTING=false"
set "UV_CACHE_DIR=%~dp0state\uv-cache"
set "PATH=%~dp0.venv\Scripts;%PATH%"
"%~dp0.venv\Scripts\serena.exe" start-mcp-server --context codex --project "D:\Users\New project 1" --enable-web-dashboard false --open-web-dashboard false
