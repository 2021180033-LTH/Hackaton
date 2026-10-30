@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
cl /nologo /std:c++17 /utf-8 /EHsc /O2 /MD /DUNICODE /D_UNICODE src\server.cpp /Fobuild\server.obj /FeForensic_G.exe /link bcrypt.lib crypt32.lib ws2_32.lib shell32.lib
exit /b %errorlevel%
