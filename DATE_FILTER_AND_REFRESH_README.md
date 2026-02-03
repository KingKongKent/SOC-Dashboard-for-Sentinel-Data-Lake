# 🎯 SOC Dashboard - Date Filter & Hourly Auto-Refresh

## ✅ What's New

### 1. **Date Range Filter** 📅
Your dashboard now has a date range dropdown in the header:
- **Last 7 Days**
- **Last 30 Days** (default)
- **Last 60 Days**
- **Last 90 Days**
- **All Time**

The filter immediately updates the dashboard with data from the selected time range.

### 2. **Hourly Auto-Refresh** 🔄
- **Frontend**: Dashboard automatically refreshes every 60 minutes
- **Backend**: New data fetched from Defender every hour
- **Database**: Appends new incidents/alerts without rewriting everything

---

## 🚀 Quick Start

### Test the Date Filter

1. **Open Dashboard**: http://localhost:5000
2. **Look at Header**: Find the date range dropdown (top right)
3. **Select "Last 7 Days"**: Dashboard reloads with only last week's data
4. **Try Other Ranges**: Switch between 7d, 30d, 60d, 90d, or All Time
5. **Check "Last refresh"**: Shows when data was last updated

### Start Hourly Refresh Service

**Option 1: Simple (Manual)**
```bash
python hourly_refresh.py
```
- Runs in terminal window
- Refreshes every hour on the hour
- Press Ctrl+C to stop

**Option 2: Windows Task Scheduler (Automatic)**
```powershell
# Run as Administrator
powershell -ExecutionPolicy Bypass -File setup_task_scheduler.ps1
```
- Creates scheduled task
- Runs in background automatically
- Survives reboots

**Option 3: Batch File (Simple)**
```bash
start_hourly_refresh.bat
```
- Double-click to start
- Runs in command window
- Close window to stop

---

## 📊 How It Works

### Date Filter Flow:
```
User selects "Last 7 Days"
    ↓
Frontend: Sets currentFilters.days = 7
    ↓
API Call: GET /api/dashboard-data?days=7
    ↓
Backend: Queries database WHERE created_time >= 7 days ago
    ↓
Returns: Only incidents/alerts from last 7 days
    ↓
Frontend: Updates charts, tables, metrics
```

### Hourly Refresh Flow:
```
Hour Mark (e.g., 14:00)
    ↓
hourly_refresh.py triggers
    ↓
Fetches new incidents from Defender API
    ↓
Checks database for existing incident IDs
    ↓
Inserts ONLY new incidents/alerts
    ↓
Updates threat intelligence
    ↓
Frontend auto-refreshes (if open)
```

---

## 🎛️ Configuration

### Change Auto-Refresh Interval

**Frontend** (dashboard refresh):
Edit line in `soc-dashboard-live.html`:
```javascript
startAutoRefresh(60);  // Change 60 to desired minutes
```

**Backend** (data fetch):
Edit `hourly_refresh.py`:
```python
schedule.every().hour.at(":00").do(hourly_refresh_job)
# Change to:
schedule.every(30).minutes.do(hourly_refresh_job)  # Every 30 min
```

### Add More Date Range Options

Edit `soc-dashboard-live.html`:
```html
<select id="dateRangeFilter" ...>
    <option value="1">Last 24 Hours</option>  <!-- Add this -->
    <option value="7">Last 7 Days</option>
    <option value="14">Last 2 Weeks</option>  <!-- Add this -->
    ...
</select>
```

---

## 📋 API Endpoints

### With Date Filtering:
```bash
# Last 7 days
curl "http://localhost:5000/api/dashboard-data?days=7"

# Last 30 days
curl "http://localhost:5000/api/dashboard-data?days=30"

# Last 90 days
curl "http://localhost:5000/api/dashboard-data?days=90"

# All time (no filter)
curl "http://localhost:5000/api/dashboard-data"

# Combine with severity
curl "http://localhost:5000/api/dashboard-data?days=7&severity=High"
```

### Response Includes Filters:
```json
{
  "timestamp": "2026-02-03T...",
  "dataSource": "sqlite_database",
  "filters": {
    "days": 7,
    "severity": null,
    "status": null
  },
  "incidents": [...],
  "alerts": [...]
}
```

---

## 🔍 Monitoring

### Check Hourly Refresh Status

**If running in terminal:**
- Watch console output for refresh messages
- See new incidents/alerts count each hour

**If running as scheduled task:**
```powershell
# Check last run time
Get-ScheduledTask -TaskName "SOC_Dashboard_Hourly_Refresh" | Get-ScheduledTaskInfo

# View task history
Get-ScheduledTask -TaskName "SOC_Dashboard_Hourly_Refresh" | Get-ScheduledTaskInfo | Select-Object LastRunTime, LastTaskResult, NextRunTime
```

### Check Database Growth

```bash
# See database stats
curl http://localhost:5000/api/database-stats

# Or run Python:
python -c "from database import get_database_stats; import json; print(json.dumps(get_database_stats(), indent=2))"
```

### View Dashboard Metrics

Open http://localhost:5000 and check:
- **Last refresh**: Shows when frontend last updated
- **Date range dropdown**: Current filter selection
- **Metrics cards**: Reflect filtered time period

---

## 🎨 UI Features

### Visual Indicators:

**Date Range Dropdown:**
- Blue border (active filter)
- Shows selected range
- Dropdown icon

**Last Refresh Time:**
- Small gray text below dropdown
- Format: HH:MM:SS (24-hour)
- Updates on every refresh

**Loading Toast:**
- Appears when changing date range
- Purple gradient background
- Slides in from right
- Auto-dismisses after 2 seconds

---

## 🆘 Troubleshooting

### Date Filter Not Working

**Check console:**
```javascript
// Open browser DevTools (F12)
// Look for:
"📊 Fetching data from: /api/dashboard-data?days=7"
```

**Check backend logs:**
```
📊 Querying database with filters:
   • Last 7 days
✅ Serving 45 incidents and 156 alerts from database
```

### Hourly Refresh Not Running

**Check script is running:**
```powershell
Get-Process python | Where-Object {$_.CommandLine -like "*hourly_refresh*"}
```

**Check scheduled task:**
```powershell
Get-ScheduledTask -TaskName "SOC_Dashboard_Hourly_Refresh"
```

**Check logs:**
- Look at terminal output if running manually
- Check Task Scheduler History if using scheduled task

### Frontend Not Auto-Refreshing

**Check console:**
```javascript
// Should see every hour:
"🔄 Auto-refresh triggered"
"🔄 Refreshing dashboard data with filters: {days: 30}"
```

**Restart browser** if auto-refresh stops working

---

## 📚 Files Reference

### New Files:
- `hourly_refresh.py` - Hourly data fetch script
- `start_hourly_refresh.bat` - Simple launcher
- `setup_task_scheduler.ps1` - Windows Task Scheduler setup

### Modified Files:
- `soc-dashboard-live.html` - Added date filter dropdown and auto-refresh

### Related Files:
- `append_data.py` - Appends new data (called by hourly_refresh.py)
- `database.py` - Database queries with date filtering
- `dashboard_backend.py` - API supports ?days= parameter

---

## ✨ Benefits

### Before:
- ❌ Manual refresh only
- ❌ Fixed 30-day view
- ❌ Data stale until refresh
- ❌ No time range control

### After:
- ✅ Auto-refresh every hour (frontend + backend)
- ✅ 5 date range options (7d, 30d, 60d, 90d, all)
- ✅ Always up-to-date data
- ✅ Filter by any time period

---

## 🎉 You're Done!

Your dashboard now has:
- ✅ **Date range filter** with 5 options
- ✅ **Hourly auto-refresh** (frontend)
- ✅ **Hourly data fetch** (backend)
- ✅ **Last refresh timestamp**
- ✅ **Smooth loading indicators**

**Open http://localhost:5000 and try it!** 🚀
