@echo off
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0deploy\desktop-client.ps1"
if errorlevel 1 pause
