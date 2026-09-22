@echo off
rem Builds RostorCredProv.dll (x64 Release) with MSVC Build Tools 2022.
rem Run from any directory; output lands in %~dp0out\.
setlocal
set VCVARS="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist %VCVARS% (
    echo vcvars64.bat not found at %VCVARS%
    exit /b 1
)
call %VCVARS% >nul
if errorlevel 1 exit /b 1

set SRC=%~dp0
set OUT=%~dp0out
if not exist "%OUT%" mkdir "%OUT%"
pushd "%OUT%"

cl.exe /nologo /W4 /WX /EHsc /O2 /MT /GS /guard:cf /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /std:c++17 ^
    /c "%SRC%dll.cpp" "%SRC%Provider.cpp" "%SRC%Credential.cpp" "%SRC%helpers.cpp" ^
    "%SRC%pipeclient.cpp" "%SRC%json.cpp" "%SRC%log.cpp"
if errorlevel 1 ( popd & exit /b 1 )

link.exe /nologo /DLL /OUT:"%OUT%\RostorCredProv.dll" /DEF:"%SRC%RostorCredProv.def" ^
    /NXCOMPAT /DYNAMICBASE /GUARD:CF /RELEASE ^
    dll.obj Provider.obj Credential.obj helpers.obj pipeclient.obj json.obj log.obj ^
    ole32.lib shlwapi.lib advapi32.lib secur32.lib kernel32.lib user32.lib
if errorlevel 1 ( popd & exit /b 1 )

popd
echo Built %OUT%\RostorCredProv.dll
endlocal
