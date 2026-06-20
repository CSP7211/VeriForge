@echo off
REM ==============================================================================
REM  VeriForge SDK - Windows Batch Wrapper
REM ==============================================================================
REM This wrapper finds the best available Python installation (3.10+) and runs
REM the VeriForge SDK module. It handles common installation locations and
REM provides helpful error messages if Python is missing.
REM
REM Usage:
REM   veriforge-sdk <command> [options]
REM
REM Commands:
REM   scan <path>          Scan a directory for vulnerabilities
REM   dashboard            Launch the security dashboard
REM   audit                Run privacy audit
REM   --help               Show all available commands
REM
REM For more information: https://docs.veriforge.dev
REM ==============================================================================

echo.
setlocal enabledelayedexpansion
set "PYTHON_CMD="
set "PYTHON_VER="
set "BEST_PYTHON="
set "BEST_VER_MAJOR=0"
set "BEST_VER_MINOR=0"

REM ============================================================================
REM  Step 1: Check PATH for python / python3 / py
REM ============================================================================
for %%P in (python python3 py) do (
    where /q %%P 2>nul
    if !errorlevel! == 0 (
        for /f "tokens=*" %%V in ('%%P -c "import sys; v=sys.version_info; print(f'{v.major}.{v.minor}.{v.micro}')" 2^>nul') do (
            set "FOUND_VER=%%V"
            for /f "tokens=1,2 delims=." %%A in ("%%V") do (
                set "V_MAJOR=%%A"
                set "V_MINOR=%%B"
                if !V_MAJOR! GEQ 3 (
                    if !V_MINOR! GEQ 10 (
                        if !V_MAJOR! GTR !BEST_VER_MAJOR! (
                            set "BEST_PYTHON=%%P"
                            set "BEST_VER_MAJOR=!V_MAJOR!"
                            set "BEST_VER_MINOR=!V_MINOR!"
                        ) else if !V_MAJOR! EQU !BEST_VER_MAJOR! (
                            if !V_MINOR! GTR !BEST_VER_MINOR! (
                                set "BEST_PYTHON=%%P"
                                set "BEST_VER_MAJOR=!V_MAJOR!"
                                set "BEST_VER_MINOR=!V_MINOR!"
                            )
                        )
                    )
                )
            )
        )
    )
)

if not "!BEST_PYTHON!"=="" (
    set "PYTHON_CMD=!BEST_PYTHON!"
    goto :found
)

REM ============================================================================
REM  Step 2: Check specific Python installation directories
REM ============================================================================
for %%D in (
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
    "C:\Python312\python.exe"
    "C:\Python311\python.exe"
    "C:\Python310\python.exe"
    "%ProgramFiles%\Python312\python.exe"
    "%ProgramFiles%\Python311\python.exe"
    "%ProgramFiles%\Python310\python.exe"
    "%ProgramFiles(x86)%\Python312\python.exe"
    "%ProgramFiles(x86)%\Python311\python.exe"
    "%ProgramFiles(x86)%\Python310\python.exe"
) do (
    if exist "%%D" (
        set "PYTHON_CMD=%%D"
        goto :found
    )
)

REM ============================================================================
REM  Step 3: Check Windows Store Python
REM ============================================================================
if exist "%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe" (
    set "PYTHON_CMD=%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe"
    goto :found
)

REM ============================================================================
REM  Error: No compatible Python found
REM ============================================================================
echo  ===================================================================
echo    ERROR: Python 3.10+ not found
echo  ===================================================================
echo.
echo    VeriForge requires Python 3.10 or later to run.
echo.
echo    Please install Python from: https://www.python.org/downloads/
echo.
echo    During installation, make sure to check:
echo      [X] Add Python to PATH
echo      [X] Install for all users (recommended)
echo.
echo    After installing Python, open a NEW terminal and try again.
echo.
echo    Installed Python but still seeing this? Try:
echo      set PATH=%%PATH%%;C:\Users\%%USERNAME%%\AppData\Local\Programs\Python\Python312
echo      set PATH=%%PATH%%;C:\Users\%%USERNAME%%\AppData\Local\Programs\Python\Python312\Scripts
echo.
set /p "choice=    Open browser to python.org? [Y/n]: "
if /i "!choice!"=="n" goto :end
if /i "!choice!"=="no" goto :end
start https://www.python.org/downloads/
:end
echo.
pause
exit /b 1

REM ============================================================================
REM  Found Python - Run the SDK
REM ============================================================================
:found
REM echo  Using Python: %PYTHON_CMD%
%PYTHON_CMD% -m veriforge_sdk %*
set "SDK_EXIT=%errorlevel%"
exit /b %SDK_EXIT%
