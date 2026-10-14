@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy\windows-client.ps1" -Action start
if errorlevel 1 pause
