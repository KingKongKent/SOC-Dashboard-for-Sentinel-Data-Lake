# SOC Dashboard - SQLite Migration Guide

## 🎯 What Changed

Your SOC Dashboard now uses **SQLite database** instead of regenerating a JSON file on every refresh. This enables:

✅ **Append-only operations** - Add new data without rewriting everything  
✅ **Timeline filtering** - Query by date range (last 7 days, 30 days, custom range)  
✅ **Historical data** - Keep incidents indefinitely  
✅ **Faster queries** - Indexed database vs. file reading  
✅ **Flexible filtering** - Filter by severity, status, date range  

## 📁 New Files Created

- `database.py` - SQLite schema and query functions
- `migrate_json_to_db.py` - One-time migration from JSON to SQLite
- `append_data.py` - Fetch new data and append to database
- `rollback_to_json.py` - Restore original JSON system if needed

## 🚀 Migration Steps

### 1. Initialize Database & Migrate Existing Data

```bash
python migrate_json_to_db.py
```

This will:
- Create `soc_dashboard.db`
- Import all 100 incidents from `dashboard_data.json`
- Import all 311 alerts
- Extract and index all entities
- Preserve threat intelligence

### 2. Stop Old Backend (if running)

```powershell
Get-Process python | Where-Object {$_.CommandLine -like "*dashboard_backend*"} | Stop-Process -Force
```

### 3. Start New Backend

```bash
python dashboard_backend.py
```

The backend now:
- Queries SQLite by default
- Supports timeline filtering via query parameters
- Falls back to JSON if database unavailable

### 4. Test the Dashboard

Open: http://localhost:5000

Your frontend **doesn't need changes** - API returns same JSON format!

## 🔄 Appending New Data

Instead of regenerating everything, append new data:

```bash
python append_data.py
```

This script:
- Fetches new incidents from Defender
- Checks what's already in database
- Inserts only NEW incidents/alerts
- Updates threat intelligence
- Much faster than full regeneration!

**Schedule this to run every 15-30 minutes** for real-time updates.

## 🎛️ Timeline Filtering (New Feature!)

The API now supports query parameters:

### Last N Days
```
GET /api/dashboard-data?days=7      # Last 7 days
GET /api/dashboard-data?days=30     # Last 30 days (default)
GET /api/dashboard-data?days=90     # Last 90 days
```

### Date Range
```
GET /api/dashboard-data?start_date=2026-01-01&end_date=2026-02-03
```

### Filter by Severity
```
GET /api/dashboard-data?severity=High
GET /api/dashboard-data?severity=Medium
```

### Filter by Status
```
GET /api/dashboard-data?status=Active
GET /api/dashboard-data?status=Resolved
```

### Combine Filters
```
GET /api/dashboard-data?days=7&severity=High&status=Active
```

## 📊 Database Statistics

Check what's in your database:

```bash
GET /api/database-stats
```

Returns:
- Total incidents, alerts, entities
- Date range of data
- Database health info

## ⏮️ Rollback to JSON (If Needed)

If something breaks, restore the original system:

```bash
python rollback_to_json.py
```

This will:
- Restore `fetch_live_data.py` (original)
- Restore `dashboard_backend.py` (original)
- Restore `dashboard_data.json` (original data)
- Keep database as backup
- System reverts to JSON mode

## 🗂️ File Structure

```
Demo1/
├── soc_dashboard.db              # SQLite database (NEW)
├── database.py                   # Database operations (NEW)
├── migrate_json_to_db.py         # Migration script (NEW)
├── append_data.py                # Append new data (NEW)
├── rollback_to_json.py           # Rollback script (NEW)
├── dashboard_backend.py          # Updated with DB queries
├── fetch_live_data.py            # Original (kept for functions)
├── dashboard_data.json.backup    # Your backup (SAFE)
├── dashboard_backend.py.backup   # Your backup (SAFE)
└── fetch_live_data.py.backup     # Your backup (SAFE)
```

## 🔒 Safety Features

1. **Backups Created**: All original files backed up with `.backup` extension
2. **Fallback Mode**: If database fails, backend falls back to JSON automatically
3. **Rollback Script**: One command to restore everything
4. **Data Preservation**: Database backed up before rollback

## 💡 Recommended Workflow

### Daily Operations:
```bash
# Append new data (run every 15-30 min)
python append_data.py

# Check database stats
curl http://localhost:5000/api/database-stats
```

### Frontend Changes (Optional):
Add timeline filter dropdown:
```javascript
// Example: Add to your dashboard
<select onchange="filterTimeline(this.value)">
  <option value="7">Last 7 Days</option>
  <option value="30">Last 30 Days</option>
  <option value="90">Last 90 Days</option>
</select>

function filterTimeline(days) {
  fetch(`/api/dashboard-data?days=${days}`)
    .then(r => r.json())
    .then(data => updateDashboard(data));
}
```

## 🆘 Troubleshooting

### Database not found error
```bash
python migrate_json_to_db.py
```

### Dashboard shows no data
```bash
python append_data.py
```

### Something broke
```bash
python rollback_to_json.py
```

### Check backend mode
Look for startup message:
- ✅ "Database mode: SQLite with timeline filtering" = Working!
- ⚠️ "JSON fallback mode" = Database not available

## 📈 Performance Benefits

**Before (JSON):**
- Regenerate 100 incidents + 311 alerts every time
- ~5-10 seconds to regenerate
- No historical data
- Can't filter by date range

**After (SQLite):**
- Append only new data (~0.5 seconds)
- Query any date range instantly
- Keep historical data forever
- Filter by severity, status, date range
- Efficient queries with indexes

## 🎉 You're Ready!

Your dashboard now has:
- ✅ Database persistence
- ✅ Append-only updates
- ✅ Timeline filtering
- ✅ Historical data
- ✅ Safe rollback option

Run the migration and enjoy your upgraded SOC dashboard! 🚀
