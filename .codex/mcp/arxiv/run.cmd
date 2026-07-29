@echo off
setlocal
set "ARXIV_MCP_STORAGE=%~dp0cache"
"%~dp0.venv\Scripts\arxiv-mcp-server.exe" --storage-path "%ARXIV_MCP_STORAGE%"
