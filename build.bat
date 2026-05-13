@echo off
rem hash-bench-n64-opt build wrapper.
rem
rem - Sets N64_INST to point at the local libdragon install.
rem - Forces TMP/TEMP to a writable dir (mips64-elf-gcc otherwise tries
rem   to write temp files into C:\Windows\ when run via cmd, which fails).
rem - Pre-deletes the .z64 so a stale file held by a running emulator
rem   doesn't fail the make recipe at its own `rm -f $@` step.

setlocal enableextensions
set N64_INST=I:/libdragon
set TMP=C:\tmp
set TEMP=C:\tmp
if not exist C:\tmp mkdir C:\tmp
set PATH=I:\libdragon\bin;C:\ProgramData\mingw64\mingw64\bin;%PATH%
cd /d "%~dp0"
if not exist build mkdir build

rem If the previous .z64 is locked (e.g. an emulator has it open), try to
rem rename it out of the way first. Renaming usually works even when delete
rem doesn't, because Windows allows renaming files that are open with
rem FILE_SHARE_DELETE — most emulators leave that flag on.
if exist hash-bench-n64-opt.z64 (
    move /Y hash-bench-n64-opt.z64 hash-bench-n64-opt.prev.z64 >nul 2>nul
    if errorlevel 1 (
        echo WARNING: hash-bench-n64-opt.z64 is locked by another process.
        echo          Close your emulator and rerun build.bat.
    )
)

I:\libdragon\bin\make.exe N64_INST=I:/libdragon 2>build\build.err
set MAKE_RC=%errorlevel%

if %MAKE_RC% NEQ 0 (
    echo Build FAILED. See build\build.err
    type build\build.err
    exit /b 1
)
if not exist hash-bench-n64-opt.z64 (
    echo Build did not produce hash-bench-n64-opt.z64
    type build\build.err
    exit /b 1
)

rem Successful build — discard the renamed previous artifact.
if exist hash-bench-n64-opt.prev.z64 del /q hash-bench-n64-opt.prev.z64

echo Build OK: %~dp0hash-bench-n64-opt.z64
type build\build.err 2>nul
endlocal
