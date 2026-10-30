@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
if "%FORENSIC_TORCH%"=="" set "FORENSIC_TORCH=%~dp0..\work\video_noise_runtime\Lib\site-packages\torch"
if not exist build mkdir build
cl /nologo /std:c++17 /utf-8 /EHsc /O2 /MD /DUNICODE /D_UNICODE src\server.cpp /Fobuild\server.obj /FeForensic_G.exe /link bcrypt.lib crypt32.lib ws2_32.lib shell32.lib
if errorlevel 1 exit /b %errorlevel%
cl /nologo /std:c++17 /utf-8 /EHsc /O2 /MD /bigobj /LD /DUNICODE /D_UNICODE /I"%FORENSIC_TORCH%\include" /I"%FORENSIC_TORCH%\include\torch\csrc\api\include" src\engine.cpp /Fobuild\engine.obj /FeForensicEngine.dll /link /IMPLIB:build\ForensicEngine.lib /LIBPATH:"%FORENSIC_TORCH%\lib" torch.lib torch_cpu.lib c10.lib torch_cuda.lib c10_cuda.lib bcrypt.lib crypt32.lib
exit /b %errorlevel%
