@echo off
REM ============================================
REM RS485 Sniffer v1.6.2 - Build Script
REM ============================================
echo.
echo RS485 Sniffer v1.6.2 - Windows EXE Builder
echo ============================================
echo.

REM Check if PyInstaller is installed
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

REM Check if pyserial is installed
pip show pyserial >nul 2>&1
if errorlevel 1 (
    echo Installing pyserial...
    pip install pyserial
)

echo.
echo Building EXE...
echo.

REM Build with spec file
pyinstaller --clean rs485_sniffer_v1.6.2.spec

echo.
echo ============================================
if exist "dist\RS485_Sniffer\RS485_Sniffer.exe" (
    echo SUCCESS! EXE created at:
    echo   dist\RS485_Sniffer\RS485_Sniffer.exe
    echo.
    echo To run: dist\RS485_Sniffer\RS485_Sniffer.exe
) else (
    echo ERROR: Build failed!
    echo Check the output above for errors.
)
echo ============================================
echo.
pause
