@echo off
title LaptopShield Pro - Endpoint Hardening
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"
set PYTHONPATH=%~dp0src
start "" pythonw -m laptopshield.ui.app
if %errorlevel% neq 0 (
    python -m laptopshield.ui.app
    pause
)
