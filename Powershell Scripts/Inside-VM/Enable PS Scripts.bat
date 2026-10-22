@echo off
setlocal EnableDelayedExpansion

:: Check for administrator privileges and auto-elevate if needed
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo.
    echo ========================================
    echo Requesting Administrator Privileges...
    echo ========================================
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd.exe -ArgumentList '/c `\"`\"%~f0`\" %*`\"' -Verb RunAs" 2>nul
    if %errorlevel% EQU 0 (
        exit /b 0
    )
    echo.
    echo ========================================
    echo ERROR: Administrator rights required!
    echo ========================================
    echo.
    echo This script must be run as Administrator to modify system policies.
    echo.
    echo Right-click this file and select "Run as administrator".
    echo.
    if /i "%~1"=="/quiet" exit /b 1
    if /i "%~1"=="/y" exit /b 1
    if /i "%~1"=="-y" exit /b 1
    pause
    exit /b 1
)

:: Set working directory to script location
cd /d "%~dp0"

echo.
echo ========================================
echo PowerShell Script Enabler
echo ========================================
echo.
echo This script will:
echo  - Set PowerShell execution policy to Unrestricted (64-bit and 32-bit)
echo  - Enable script execution in Windows Machine Policies
echo  - Unblock all PowerShell scripts in the CloakBox directory
echo.
echo WARNING: This reduces security. Only proceed if you trust
echo          the PowerShell scripts in this directory.
echo.

:: Support silent execution via /y or -y or /quiet
if /i "%~1"=="/y" goto proceed
if /i "%~1"=="-y" goto proceed
if /i "%~1"=="/quiet" goto proceed

choice /M "Do you wish to proceed"
if errorlevel 2 goto abort

:proceed
echo.
echo [1/5] Setting ExecutionPolicy in PowerShell Registry (64-bit and 32-bit)...
reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Unrestricted" /f >nul 2>&1
reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Unrestricted" /f >nul 2>&1
echo [OK] Registry ExecutionPolicy configured.

echo.
echo [2/5] Setting ExecutionPolicy in Windows Machine Policies...
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Unrestricted" /f >nul 2>&1
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\PowerShell" /v "EnableScripts" /t REG_DWORD /d "1" /f >nul 2>&1
reg.exe add "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows\PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Unrestricted" /f >nul 2>&1
reg.exe add "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows\PowerShell" /v "EnableScripts" /t REG_DWORD /d "1" /f >nul 2>&1
echo [OK] Windows Policies ExecutionPolicy set.

echo.
echo [3/5] Applying ExecutionPolicy via PowerShell cmdlets (LocalMachine ^& CurrentUser)...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "try { Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force -ErrorAction SilentlyContinue } catch {}; try { Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force -ErrorAction SilentlyContinue } catch {}" >nul 2>&1
echo [OK] Scoped ExecutionPolicies applied.

echo.
echo [4/5] Unblocking scripts across the CloakBox workspace...
set "TARGET_DIR=%~dp0"
if exist "%~dp0..\..\Powershell Scripts" (
    pushd "%~dp0..\.."
    set "TARGET_DIR=!CD!"
    popd
) else if exist "%~dp0..\Powershell Scripts" (
    pushd "%~dp0.."
    set "TARGET_DIR=!CD!"
    popd
) else if exist "%~dp0..\..\Utilities" (
    pushd "%~dp0..\.."
    set "TARGET_DIR=!CD!"
    popd
) else if exist "%~dp0..\Utilities" (
    pushd "%~dp0.."
    set "TARGET_DIR=!CD!"
    popd
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path '%TARGET_DIR%' -Recurse -Include '*.ps1','*.psm1','*.psd1','*.bat' -ErrorAction SilentlyContinue | Unblock-File -Confirm:$false -ErrorAction SilentlyContinue"
echo [OK] Scripts in '%TARGET_DIR%' unblocked.

echo.
echo [5/5] Verifying effective PowerShell ExecutionPolicy...
for /f "usebackq delims=" %%P in (`powershell.exe -NoProfile -Command "Get-ExecutionPolicy" 2^>nul`) do set "CURRENT_POLICY=%%P"
echo [OK] Current effective ExecutionPolicy: %CURRENT_POLICY%

echo.
echo ========================================
echo SUCCESS! PowerShell scripts enabled.
echo ========================================
echo.
echo You can now run all CloakBox PowerShell scripts without restrictions.
echo.
goto end

:abort
echo.
echo ========================================
echo Script execution aborted by user
echo ========================================
echo.

:end
if /i "%~1"=="/quiet" exit /b 0
if /i "%~1"=="/y" exit /b 0
if /i "%~1"=="-y" exit /b 0
pause
exit /b 0