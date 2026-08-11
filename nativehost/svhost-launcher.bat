@echo off
if exist "%~dp0svhost.exe" (
  "%~dp0svhost.exe" %*
) else (
  python "%LOCALAPPDATA%\SecureVault\src\svhost.py" %*
)
