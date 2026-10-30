@echo off
rem Builds MarkTool.exe (window) and ForensicMark.exe (command line) with Visual Studio 2022. No other dependencies.
setlocal
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR (echo Visual Studio C++ tools not found & exit /b 1)
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
cd /d "%~dp0"
if not exist build mkdir build
cl /nologo /std:c++17 /utf-8 /EHsc /O2 /W4 /permissive- /DUNICODE /D_UNICODE src\marktool.cpp /Fobuild\ /Fdbuild\ /FeMarkTool.exe /link /SUBSYSTEM:WINDOWS || exit /b 1
cl /nologo /std:c++17 /utf-8 /EHsc /O2 /W4 /permissive- /DUNICODE /D_UNICODE src\cli.cpp /Fobuild\ /Fdbuild\ /FeForensicMark.exe || exit /b 1
echo Built MarkTool.exe, ForensicMark.exe
