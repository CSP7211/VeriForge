@echo off
title VeriForge Red — Live Desktop Dashboard
color 0A
cls

echo ================================================
echo   VeriForge Red — Live Desktop Dashboard
echo ================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found.
    echo Please install Python from https://python.org/downloads
    echo Make sure to check "Add Python to PATH"
    pause
    exit /b 1
)
echo [OK] Python found
python --version

:: Check Git
git --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Git not found.
    echo Please install Git from https://git-scm.com/download/win
    pause
    exit /b 1
)
echo [OK] Git found

:: Set repo directory
set VF_DIR=%USERPROFILE%\veriforge-red

:: Clone or pull repo
if not exist "%VF_DIR%\.git" (
    echo [INFO] Cloning VeriForge Red from GitHub...
    cd /d %USERPROFILE%
    rmdir /s /q veriforge-red 2>nul
    git clone https://github.com/CSP7211/VeriForge.git veriforge-red
    if errorlevel 1 (
        echo [ERROR] Clone failed.
        pause
        exit /b 1
    )
) else (
    echo [INFO] Pulling latest updates...
    cd /d %VF_DIR%
    git pull origin main
)
echo [OK] Repository ready at: %VF_DIR%

:: Install dependencies (without pip install -e . to avoid version issues)
echo.
echo [INFO] Installing dependencies...
python -m pip install --upgrade pip
python -m pip install PyJWT pytest

:: Generate secrets
for /f "delims=" %%a in ('python -c "import secrets; print(secrets.token_hex(32))"') do set "VERIFORGE_SECRET=%%a"
for /f "delims=" %%a in ('python -c "import secrets; print(secrets.token_hex(32))"') do set "VERIFORGE_JWT_SECRET=%%a"
for /f "delims=" %%a in ('python -c "import secrets; print(secrets.token_hex(32))"') do set "VERIFORGE_AUDIT_SECRET=%%a"

:: Start server using PYTHONPATH (no pip install needed)
echo.
echo [INFO] Starting VeriForge Red Live Server...
echo   Dashboard will open at: http://localhost:8080
echo   Press Ctrl+C to stop
echo.

cd /d %VF_DIR%
set PYTHONPATH=%VF_DIR%;%PYTHONPATH%
python veriforge_server.py

echo.
echo Server stopped.
pause
