@echo off
rem Builds and runs json_test.exe (self-test of json.cpp) and builds cp_test.exe,
rem a harness that drives the built DLL like LogonUI would (run it elevated:
rem   out\cp_test.exe out\RostorCredProv.dll testuser x [expect-ok|expect-deny]
rem   out\cp_test.exe out\RostorCredProv.dll --badge 5555555555 2468 expect-ok
rem   out\cp_test.exe out\RostorCredProv.dll --badge-plain 1234567890 - expect-ok).
rem cp_test links pipeclient.cpp so it can read the deputy's `ui` reply itself.
setlocal
set VCVARS="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist %VCVARS% ( echo vcvars64.bat not found & exit /b 1 )
call %VCVARS% >nul
set SRC=%~dp0
set OUT=%~dp0out
if not exist "%OUT%" mkdir "%OUT%"
pushd "%OUT%"
cl.exe /nologo /W4 /WX /EHsc /O2 /MT /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /std:c++17 ^
    /Fe:json_test.exe "%SRC%json_test.cpp" "%SRC%json.cpp" "%SRC%log.cpp" kernel32.lib
if errorlevel 1 ( popd & exit /b 1 )
json_test.exe
set RC=%ERRORLEVEL%
if not "%RC%"=="0" ( popd & exit /b %RC% )
cl.exe /nologo /W4 /WX /EHsc /O2 /MT /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /std:c++17 ^
    /Fe:cp_test.exe "%SRC%cp_test.cpp" "%SRC%json.cpp" "%SRC%log.cpp" "%SRC%pipeclient.cpp" kernel32.lib ole32.lib shlwapi.lib
set RC=%ERRORLEVEL%
popd
exit /b %RC%
