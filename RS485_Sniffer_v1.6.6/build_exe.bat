@echo off
echo ========================================
echo RS485 Sniffer v1.6.6 Build Script
echo ========================================
echo.

REM Check Python
python --version
if errorlevel 1 (
    echo ERROR: Python not found!
    pause
    exit /b 1
)

REM Install dependencies
echo Installing dependencies...
pip install pyserial pyinstaller

REM Build EXE
echo.
echo Building EXE...
pyinstaller --clean rs485_sniffer.spec

echo.
echo Build complete!
echo EXE location: dist\RS485_Sniffer_v1.6.6.exe
echo.
pause
