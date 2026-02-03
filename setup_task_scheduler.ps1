# Setup Windows Task Scheduler for Hourly Data Refresh
# Run this script as Administrator to create a scheduled task

$taskName = "SOC_Dashboard_Hourly_Refresh"
$scriptPath = Join-Path $PSScriptRoot "hourly_refresh.py"
$pythonPath = (Get-Command python).Source

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SOC Dashboard - Task Scheduler Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "❌ Error: This script must be run as Administrator" -ForegroundColor Red
    Write-Host ""
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

# Check if Python is installed
if (-not $pythonPath) {
    Write-Host "❌ Error: Python not found in PATH" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please ensure Python is installed and added to PATH" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

Write-Host "✅ Python found: $pythonPath" -ForegroundColor Green
Write-Host "✅ Script path: $scriptPath" -ForegroundColor Green
Write-Host ""

# Remove existing task if it exists
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Host "⚠️  Removing existing task..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

# Create scheduled task action
$action = New-ScheduledTaskAction -Execute $pythonPath -Argument "`"$scriptPath`"" -WorkingDirectory $PSScriptRoot

# Create trigger - runs every hour
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration ([TimeSpan]::MaxValue)

# Create settings
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable

# Register the task
Write-Host "📅 Creating scheduled task..." -ForegroundColor Cyan
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description "Automatically refreshes SOC Dashboard data every hour by fetching new incidents from Microsoft Defender"

Write-Host ""
Write-Host "✅ Scheduled task created successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "📊 Task Details:" -ForegroundColor Cyan
Write-Host "   • Name: $taskName"
Write-Host "   • Schedule: Every hour"
Write-Host "   • Script: hourly_refresh.py"
Write-Host "   • Database: soc_dashboard.db"
Write-Host ""
Write-Host "💡 To manage the task:" -ForegroundColor Yellow
Write-Host "   • Open Task Scheduler (taskschd.msc)"
Write-Host "   • Find: $taskName"
Write-Host "   • Right-click to Run, Disable, or Delete"
Write-Host ""
Write-Host "🔄 To start the task immediately:" -ForegroundColor Yellow
Write-Host "   Start-ScheduledTask -TaskName '$taskName'"
Write-Host ""

# Ask if user wants to start immediately
$startNow = Read-Host "Start the task now? (Y/N)"
if ($startNow -eq 'Y' -or $startNow -eq 'y') {
    Write-Host ""
    Write-Host "🚀 Starting task..." -ForegroundColor Cyan
    Start-ScheduledTask -TaskName $taskName
    Write-Host "✅ Task started!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Check the Task Scheduler for execution status" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
pause
