@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy\windows-client.ps1" -Action status
pause
