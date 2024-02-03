@echo off

for /f "delims=" %%i in ('powershell -command "Get-ExecutionPolicy -Scope CurrentUser"') do set policy=%%i

if "%policy%" NEQ "RemoteSigned" (
    echo powershell -command "Set-ExecutionPolicy -ExecutionPolicy %policy% -Scope CurrentUser" > Remove_ExecutionPolicy.cmd
    powershell -command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser"
)