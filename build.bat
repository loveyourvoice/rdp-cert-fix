@echo off
rem Build rdp-cert-fix.exe (x64, static CRT, requireAdministrator manifest)
setlocal
rem "(x86)" breaks for /f quoting, so run vswhere from its own directory
pushd "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer"
for /f "usebackq tokens=*" %%i in (`"%CD%\vswhere.exe" -latest -products * -property installationPath`) do set "VS=%%i"
popd
if not defined VS (echo Visual Studio not found & exit /b 1)
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1 || exit /b 1
cd /d "%~dp0"
if not exist build mkdir build
cl /nologo /std:c++17 /O2 /MT /EHsc /W4 /utf-8 /DUNICODE /D_UNICODE /Fobuild\ rdp_cert_fix.cpp ^
   /link /OUT:rdp-cert-fix.exe /SUBSYSTEM:CONSOLE ^
   /MANIFEST:EMBED /MANIFESTUAC:"level='requireAdministrator' uiAccess='false'"
