@echo off
echo ========================================
echo XSS Vulnerability Scanner
echo ========================================
echo.

if "%1"=="" (
    echo Usage: scan.bat ^<target_url^> [options]
    echo.
    echo Examples:
    echo   scan.bat https://example.com
    echo   scan.bat https://example.com --subdomains
    echo   scan.bat https://example.com --aggressive --output report
    echo.
    echo Available options:
    echo   --subdomains     Enable subdomain enumeration
    echo   --aggressive     Use all payloads and thorough testing
    echo   --output file    Save report to file
    echo   --format html    Report format (json, html, csv, xml)
    echo   --threads 10     Number of concurrent threads
    echo   --depth 3        Crawling depth
    echo.
    pause
    exit /b 1
)

set TARGET_URL=%1
shift

REM Build command line
set COMMAND=python enhanced_xss_scanner.py -u %TARGET_URL%

:parse_args
if "%1"=="" goto run_scan
set COMMAND=%COMMAND% %1
shift
goto parse_args

:run_scan
echo Starting XSS scan for: %TARGET_URL%
echo Command: %COMMAND%
echo.

%COMMAND%

if errorlevel 1 (
    echo.
    echo Scan failed! Check the error messages above.
) else (
    echo.
    echo Scan completed successfully!
)

echo.
pause
