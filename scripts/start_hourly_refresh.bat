@echo off
REM SOC Dashboard - Hourly Refresh Service
REM This script runs the hourly data refresh in the background

echo ========================================
echo SOC Dashboard - Hourly Refresh Service
echo ========================================
echo.

cd /d "%~dp0"

echo Starting hourly data refresh service...
echo.
echo This will:
echo  - Fetch new incidents from Defender every hour
echo  - Append data to soc_dashboard.db
echo  - Keep the database up to date automatically
echo.
echo Press Ctrl+C to stop the service
echo.

python hourly_refresh.py

pause
