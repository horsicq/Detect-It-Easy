:: Detect It Easy databases compressor for Windows (NTFS)
:: Coded by DosX, https://github.com/DosX-dev

@echo off

call :compact_it "db"
call :compact_it "db_extra"
call :compact_it "db_custom"

exit /b 0

:compact_it
set "path_to_dir=%~1"
if not exist "%path_to_dir%" (
    echo "%path_to_dir%" not found!
    exit /b 1
)
pushd "%path_to_dir%"
"%windir%\system32\compact.exe" "*" /C /S /F /I /A /Q /EXE:LZX >nul
if "%errorlevel%" == "0" (
    echo [V] "%path_to_dir%" compressed!
) else (
    echo [X] "%path_to_dir%" unable to compress!
)
popd
set "path_to_dir="

exit /b 0