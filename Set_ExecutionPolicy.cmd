@echo off
net session >nul 2>&1
if %errorlevel% == 0 ( goto :admin )

echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
"%temp%\getadmin.vbs"
exit /b

:admin
for /f "delims=" %%i in ('powershell -command "Get-ExecutionPolicy -Scope CurrentUser"') do set policy=%%i

if "%policy%" NEQ "RemoteSigned" (
    (
        echo @echo off
        echo net session ^>nul 2^>^&1
        echo if %%errorlevel%% == 0 ^( goto :admin ^)
        echo.
        echo echo Set UAC = CreateObject^^^("Shell.Application"^^^) ^> "%%temp%%\getadmin.vbs"
        echo echo UAC.ShellExecute "%%~s0", "", "", "runas", 1 ^>^> "%%temp%%\getadmin.vbs"
        echo "%%temp%%\getadmin.vbs"
        echo exit /b
        echo.
        echo :admin
        echo powershell -command "Set-ExecutionPolicy -ExecutionPolicy %policy% -Scope CurrentUser"
    ) > "%~dp0Remove_ExecutionPolicy.cmd"
    powershell -command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser"
)
