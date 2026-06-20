@echo off
REM ==============================================================================
REM  VeriForge Security Platform - One-Click Uninstaller
REM ==============================================================================
REM This batch file runs the VeriForge uninstaller with a convenient double-click
REM experience. It handles Python detection and provides visual feedback.
REM
REM The uninstaller removes:
REM   - pip packages (veriforge-sdk and dependencies)
REM   - Desktop shortcuts (Red Scanner, Dashboard, CLI)
REM   - PATH entries
REM   - Data directory (~/.veriforge)
REM
REM Usage:
REM   uninstall.bat              - Interactive uninstall (with prompts)
REM   uninstall.bat --yes        - Silent uninstall (no prompts)
REM   uninstall.bat --keep-data  - Uninstall but preserve scan data
REM ==============================================================================

echo.
echo  ===================================================================
echo    VeriForge Security Platform - Uninstallerecho  ===================================================================
echo.

REM Check for Python
set "PYTHON_CMD="
for %%P in (python python3 py) do (
    where /q %%P 2>nul
    if !errorlevel! == 0 (
        set "PYTHON_CMD=%%P"
        goto :found_python
    )
)

echo  WARNING: Python not found in PATH.
echo  Trying common installation locations...

for %%D in (
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
    "C:\Python312\python.exe"
    "C:\Python311\python.exe"
    "C:\Python310\python.exe"
) do (
    if exist "%%D" (
        set "PYTHON_CMD=%%D"
        goto :found_python
    )
)

echo  ERROR: Python not found. Cannot run uninstaller.
echo  You may need to manually remove VeriForge files from:
echo    %USERPROFILE%\.veriforge
echo    Desktop\VeriForge shortcuts
echo  Also remove VeriForge from your PATH environment variable.
echo.
pause
exit /b 1

:found_python
echo  Using: %PYTHON_CMD%
echo.

REM Check if uninstaller script exists
set "UNINSTALLER=%USERPROFILE%\.veriforge\uninstall.py"

if exist "%UNINSTALLER%" (
    echo  Found uninstaller: %UNINSTALLER%
    echo.
    "%PYTHON_CMD%" "%UNINSTALLER%" %*
    set "EXIT_CODE=%errorlevel%"
) else (
    echo  WARNING: Uninstaller script not found at:
    echo    %UNINSTALLER%
    echo.
    echo  Falling back to built-in uninstall logic...
    echo.
    call :fallback_uninstall
    set "EXIT_CODE=%errorlevel%"
)

echo.
if %EXIT_CODE% == 0 (
    echo  ===================================================================
    echo    Uninstall completed successfully!
    echo  ===================================================================
) else (
    echo  ===================================================================
    echo    Uninstall completed with warnings.
    echo    Some files may need manual removal.
    echo  ===================================================================
)
echo.
pause
exit /b %EXIT_CODE%

REM ==============================================================================
REM  Fallback Uninstall (if uninstall.py is missing)
REM ==============================================================================
:fallback_uninstall
echo  Running fallback uninstall...
echo.

REM Step 1: Uninstall pip packages
echo  [1/4] Uninstalling pip packages...
"%PYTHON_CMD%" -m pip uninstall veriforge-sdk veriforge-common veriforge-red veriforge-cli -y 2>nul
echo        Done.
echo.

REM Step 2: Remove desktop shortcuts
echo  [2/4] Removing desktop shortcuts...
set "DESKTOP=%USERPROFILE%\Desktop"
set "DESKTOP_ONE=%USERPROFILE%\OneDrive\Desktop"

for %%S in ("VeriForge Red Scanner" "VeriForge Dashboard" "VeriForge CLI") do (
    if exist "%DESKTOP%\%%S.lnk" (
        del "%DESKTOP%\%%S.lnk" 2>nul
        echo        Removed: %DESKTOP%\%%S.lnk
    )
    if exist "%DESKTOP_ONE%\%%S.lnk" (
        del "%DESKTOP_ONE%\%%S.lnk" 2>nul
        echo        Removed: %DESKTOP_ONE%\%%S.lnk
    )
)
echo        Done.
echo.

REM Step 3: Remove from PATH
echo  [3/4] Removing from PATH (manual step may be required)...
echo        Please remove the following from your PATH if present:
echo          %USERPROFILE%\.veriforge\bin
echo        (Control Panel -^> System -^> Environment Variables)
echo.

REM Step 4: Remove data directory
echo  [4/4] Removing data directory...
if exist "%USERPROFILE%\.veriforge" (
    rmdir /s /q "%USERPROFILE%\.veriforge" 2>nul
    if exist "%USERPROFILE%\.veriforge" (
        echo        WARNING: Some files could not be removed.
        echo        You may need to delete manually: %USERPROFILE%\.veriforge
        exit /b 1
    ) else (
        echo        Removed: %USERPROFILE%\.veriforge
    )
) else (
    echo        Directory not found (already removed?)
)
echo        Done.
echo.

exit /b 0
