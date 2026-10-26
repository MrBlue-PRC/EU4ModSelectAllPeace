@echo off
rem Build SelectAll.dll with MSVC (x64)
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
  echo [ERR] vcvars64 not found
  exit /b 1
)
cd /d "%~dp0"
cl /nologo /std:c++17 /utf-8 /O2 /W3 /LD /EHsc dllmain.cpp /Fe:selectall.dll /link user32.lib
if errorlevel 1 (
  echo [ERR] build failed
  exit /b 1
)
del dllmain.obj >nul 2>&1
echo OK: %~dp0selectall.dll
endlocal
