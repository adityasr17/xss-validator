@echo off
echo ========================================
echo XSS Vulnerability Scanner Setup
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python from https://python.org
    pause
    exit /b 1
)

echo Python is installed. Starting setup...
echo.

REM Run the setup script
python setup.py

if errorlevel 1 (
    echo.
    echo Setup failed! Please check the error messages above.
    pause
    exit /b 1
)

echo.
echo ========================================
echo Setup completed successfully!
echo ========================================
echo.
echo You can now run the scanner using:
echo   python enhanced_xss_scanner.py -u https://example.com
echo.
echo For simple scanning without heavy dependencies:
echo   python simple_xss_scanner.py -u https://example.com
echo.
pause
