@echo off
rem Build rdp-cert-fix.exe (x64, static CRT, GUI, manifest from res\app.manifest)
setlocal
rem "(x86)" breaks for /f quoting, so run vswhere from its own directory
pushd "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer"
for /f "usebackq tokens=*" %%i in (`"%CD%\vswhere.exe" -latest -products * -property installationPath`) do set "VS=%%i"
popd
if not defined VS (echo Visual Studio not found & exit /b 1)
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1 || exit /b 1
cd /d "%~dp0"
if not exist build mkdir build
rc /nologo /fo build\app.res res\app.rc || exit /b 1
cl /nologo /std:c++17 /O2 /MT /EHsc /W3 /utf-8 /DUNICODE /D_UNICODE /DNDEBUG ^
   /Ivendor\imgui /Fobuild\ ^
   src\main.cpp src\core.cpp ^
   vendor\imgui\imgui.cpp vendor\imgui\imgui_draw.cpp vendor\imgui\imgui_tables.cpp vendor\imgui\imgui_widgets.cpp ^
   vendor\imgui\backends\imgui_impl_dx11.cpp vendor\imgui\backends\imgui_impl_win32.cpp ^
   build\app.res ^
   /link /OUT:rdp-cert-fix.exe /SUBSYSTEM:WINDOWS /MANIFEST:NO user32.lib gdi32.lib || exit /b 1
echo OK
