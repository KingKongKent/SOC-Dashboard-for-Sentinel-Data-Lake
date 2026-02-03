# SOC Dashboard - Live Security Operations Center

Real-time security dashboard with **Microsoft Defender**, **Microsoft Sentinel**, and **Threat Intelligence** integration. Features SQLite database for historical data, timeline filtering, and automated hourly refresh.

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Credentials
Create a `.env` file with your Azure credentials:
```env
# Azure AD Application
CLIENT_ID=your-app-id-here
CLIENT_SECRET=your-client-secret-here
TENANT_ID=your-tenant-id-here

# Microsoft Sentinel Workspace
SENTINEL_WORKSPACE_ID=your-workspace-id-here
SENTINEL_WORKSPACE_NAME=your-workspace-name

# Optional: External Threat Intel API Keys
VIRUSTOTAL_API_KEY=your-virustotal-key
TALOS_API_KEY=your-talos-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
```

**⚠️ IMPORTANT**: Never commit the `.env` file to version control. It's already in `.gitignore`.

### 3. Verify Security
Before committing code, verify no secrets are exposed:
```bash
# Check that .env is gitignored
git check-ignore .env
# Should output: .env

# Verify no credentials in tracked files
git grep -E "(CLIENT_ID|CLIENT_SECRET|TENANT_ID|API_KEY)" -- '*.py' '*.md'
# Should return no hardcoded credentials
```

### 3. Verify Security
Before committing code, verify no secrets are exposed:
```bash
# Check that .env is gitignored
git check-ignore .env
# Should output: .env

# Verify no credentials in tracked files
git grep -E "(CLIENT_ID|CLIENT_SECRET|TENANT_ID|API_KEY)" -- '*.py' '*.md'
# Should return no hardcoded credentials
```

### 4. Initial Setup
```bash
# Fetch live data and populate database
python fetch_live_data.py

# Migrate data to SQLite (first time only)
python migrate_json_to_db.py
```

### 5. Start Dashboard Server
```bash
python dashboard_backend.py
```

### 6. Enable Automated Refresh (Optional)
```bash
# Start hourly data refresh service
python hourly_refresh.py
```

### 7. Open Dashboard
Navigate to: **http://localhost:5000**

## ✨ Features

### Real-Time Security Metrics
- **🎯 Secure Score**: 63.3% with category breakdown (Identity, Data, Device, Apps)
- **🔴 High Severity Incidents**: Real-time count from Microsoft Defender
- **📊 Total Incidents**: All incidents with timeline filtering
- **⚡ Active Incidents**: Incidents requiring immediate attention
- **✅ Resolved Incidents**: Resolution rate tracking
- **📈 Alert Volume Trends**: Historical analysis with filtering
- **🛡️ Threat Intelligence**: Multi-source threat indicators

### Timeline Filtering
- **7 Days**: Last week's incidents
- **30 Days**: Default view (last month)
- **60 Days**: Last 2 months
- **90 Days**: Last quarter
- **All Time**: Complete historical data

### Database Features
- **SQLite Storage**: Persistent incident data with indexed queries
- **Append-Only Operations**: New data added without regeneration
- **Historical Analysis**: Query incidents across any date range
- **Fast Filtering**: Indexed by date, severity, status
- **Entity Tracking**: 191+ extracted entities (IPs, users, files, devices)

### Enriched Incident Data
- ✅ **Entities Extraction**: Users, emails, IPs, files automatically identified
- ✅ **MITRE ATT&CK Mapping**: Techniques (T1566, T1204) linked to incidents
- ✅ **Actionable Recommendations**: Specific guidance for each incident
- ✅ **Evidence Verdicts**: Malicious, suspicious, or benign classification
- ✅ **Portal Integration**: Direct links to Microsoft 365 Defender portal
- ✅ **Alert Timeline**: Chronological view of related alerts

### Calculated Metrics (Real Data)
- **MTTD (Mean Time to Detect)**: Calculated from alert-to-incident timestamps
- **MTTR (Mean Time to Resolve)**: Average resolution time from resolved incidents
- **Alert Noise Ratio**: False positive rate from incident classifications

### Automated Refresh
- **Hourly Backend Refresh**: Fetches new incidents automatically
- **Frontend Auto-Refresh**: Dashboard updates every 60 minutes
- **Append-Only Updates**: Only new incidents added (efficient)
- **Windows Task Scheduler**: Optional scheduled execution

### Interactive Dashboard
- ✅ Click KPI cards to filter incidents by severity or status
- ✅ Incident details modal with entities, MITRE techniques, and recommendations
- ✅ Real recommendations from Microsoft Graph API
- ✅ Multi-source threat intelligence dashboard
- ✅ Alert volume, severity, and status visualizations

### Data Architecture
- **File-Based Caching**: Fast dashboard loads (no live API calls on page load)
- **Independent Data Refresh**: Run `fetch_live_data.py` to update data
- **Real-Time Ready**: Easy to schedule automated data fetching

## 📊 Data Sources

| Feature | Source | Status |
|---------|--------|--------|
| Secure Score | Microsoft Graph API | ✅ Real (63.3%) |
| Category Scores | Microsoft Graph API | ✅ Real |
| Recommendations | Graph API (secureScoreControlProfiles) | ✅ Real (5 items) |
| Incidents | Microsoft Defender (MCP) | ✅ Real (100 items) |
| Alerts | Microsoft Defender (MCP) | ✅ Real (316 items) |
| Entities | Extracted from incidents | ✅ Real (191 items) |
| Alert Volume | Calculated from real alerts | ✅ Real (7-90 days) |
| MTTD | Calculated from timestamps | ✅ Real |
| MTTR | Calculated from resolved incidents | ✅ Real |
| Alert Noise Ratio | Calculated from classifications | ✅ Real |
| Threat Intel (Microsoft) | Sentinel TI Indicators | ✅ Demo (1,247 IOCs) |
| Threat Intel (VirusTotal) | VirusTotal API | 📊 Demo (pending API key) |
| Threat Intel (Talos) | Cisco Talos API | 📊 Demo (pending API key) |
| Threat Intel (AbuseIPDB) | AbuseIPDB API | 📊 Demo (pending API key) |

## 📁 File Structure

```
Demo1/
├── soc-dashboard-live.html          # Frontend dashboard UI
├── dashboard_backend.py              # Flask API server (SQLite mode)
├── fetch_live_data.py                # Data collection script
├── database.py                       # SQLite database operations
├── migrate_json_to_db.py            # JSON to SQLite migration
├── append_data.py                    # Append new data to DB
├── hourly_refresh.py                # Automated hourly refresh
├── rollback_to_json.py              # Emergency rollback script
├── setup_task_scheduler.ps1         # Windows Task Scheduler setup
├── start_hourly_refresh.bat         # Windows service launcher
├── soc_dashboard.db                 # SQLite database (100+ incidents)
├── dashboard_data.json              # Legacy JSON backup
├── requirements.txt                  # Python dependencies
├── .env                             # Azure credentials (Git-ignored)
├── .gitignore                       # Prevents credential commits
├── README.md                        # This file
├── DATABASE_MIGRATION_README.md     # Migration documentation
├── DATE_FILTER_AND_REFRESH_README.md # Feature documentation
└── MIGRATION_SUCCESS.md             # Migration results
```

## 🗄️ Database Architecture

### SQLite Tables
- **incidents**: Primary incident data (100 rows)
  - Indexed: created_time, severity, status
  - Fields: id, title, severity, status, created_time, assigned_to, entities, etc.

- **alerts**: Alert data linked to incidents (316 rows)
  - Indexed: incident_id, timestamp
  - Fields: id, incident_id, title, severity, category, timestamp, etc.

- **entities**: Extracted entities from incidents (191 rows)
  - Indexed: entity_type, verdict
  - Fields: incident_id, entity_type, entity_name, verdict

- **threat_intel_snapshots**: Threat intelligence data
  - Timestamped snapshots of IOCs, malicious IPs, detections

- **metrics_snapshots**: Historical metrics
  - Daily/hourly snapshots for trend analysis

## 🔧 Configuration

### Microsoft Sentinel Workspace
Configure your workspace credentials in `.env` file:
```env
SENTINEL_WORKSPACE_ID=your-workspace-id-here
SENTINEL_WORKSPACE_NAME=your-workspace-name
```

### Azure AD Application
Configure your Azure AD app credentials in `.env` file:
```env
CLIENT_ID=your-app-id-here
TENANT_ID=your-tenant-id-here
CLIENT_SECRET=your-client-secret-here
```

**Required API Permissions**: 
- `SecurityEvents.Read.All`
- `SecurityActions.Read.All`
- `SecurityIncident.Read.All`

### External Threat Intelligence (Optional)
To enable real threat intelligence from external sources:

1. **VirusTotal**: Get API key from https://www.virustotal.com/
2. **AbuseIPDB**: Get API key from https://www.abuseipdb.com/
3. **Cisco Talos**: May require enterprise access

Add keys to `.env` file and run `python fetch_live_data.py` to fetch real data.

## 🔄 Data Refresh Workflow

### Option 1: Manual Refresh
```bash
python fetch_live_data.py     # Fetch new data
python append_data.py          # Append to database (optional)
```

### Option 2: Automated Hourly Refresh
```bash
# Run in terminal (stays active)
python hourly_refresh.py
```

### Option 3: Frontend Auto-Refresh
The dashboard automatically refreshes every 60 minutes while open in browser.

### Rollback to JSON Mode (Emergency)
```bash
python rollback_to_json.py
```

## 💻 Technologies

- **Frontend**: HTML5, CSS3, JavaScript, Chart.js 4.4.0
- **Backend**: Python 3.14, Flask 3.0.0, Flask-CORS 4.0.0
- **Database**: SQLite3 (built-in)
- **Scheduling**: schedule 1.2.0 library
- **Data Sources**: 
  - Microsoft Defender MCP (`mcp_triage_mcp_se_ListAlerts`, `mcp_triage_mcp_se_ListIncidents`)
  - Microsoft Sentinel MCP (`mcp_microsoft_sen2_query_lake`)
  - Microsoft Graph API (`/security/secureScores`, `/security/secureScoreControlProfiles`)
- **Authentication**: Azure AD OAuth2 (Client Credentials Flow)
- **Threat Intel APIs**: VirusTotal, Cisco Talos, AbuseIPDB

## 🎯 Interactive Features

### Timeline Filtering (Button-Based)
- **7d**: Last 7 days of incidents
- **30d**: Last 30 days (default)
- **60d**: Last 60 days
- **90d**: Last 90 days
- **All**: Complete historical data

### KPI Card Filtering
- **High Severity**: Click to filter incidents by High severity
- **Active Incidents**: Click to show incidents needing attention
- **Resolved Status**: Click to filter by resolved incidents
- **All Incidents**: Click to reset all filters

### Detailed Views
- **Secure Score Card**: Click to view category breakdown (Identity, Data, Device, Apps)
- **Incident Details**: Click any incident for full details with entities, MITRE techniques, and alert timeline
- **Entity Investigation**: Click entities to see threat intelligence lookups
- **MITRE ATT&CK**: Click techniques to view framework documentation
- **Threat Intelligence**: Click IOC cards to filter incidents by threat type

## 🛡️ Threat Intelligence Dashboard

The dashboard displays threat indicators from multiple sources:

### Current Metrics (Demo Data - Pending API Keys)
- **Threat Indicators**: 1,247 IOCs from Microsoft Sentinel
- **Malicious IPs**: 156 flagged IPs from AbuseIPDB
- **VirusTotal Detections**: 28 malicious files detected
- **Talos Threat Score**: 15/100 (lower is better)

### To Enable Real External Threat Intel
1. Add API keys to `.env` file
2. Run `python fetch_live_data.py`
3. Refresh dashboard to see updated metrics



## 🔒 Security Best Practices

- ✅ `.env` file is Git-ignored to prevent credential exposure
- ✅ All sensitive data (IDs, secrets, tokens) stored in `.env` only
- ✅ Never commit secrets, workspace IDs, or tenant IDs to version control
- ✅ Use separate credentials for development and production
- ✅ Backend runs on `localhost:5000` (development only)
- ⚠️ For production: Use proper WSGI server (Gunicorn, uWSGI)
- ⚠️ For production: Enable HTTPS/TLS
- ⚠️ For production: Implement rate limiting and authentication
- ⚠️ For production: Use Azure Key Vault for secrets management

## 🚧 Migration & Rollback

### Database Migration (Already Completed)
```bash
python migrate_json_to_db.py
```
- ✅ Migrated 100 incidents
- ✅ Migrated 316 alerts
- ✅ Extracted 191 entities
- ✅ Date range: 2026-01-09 to 2026-02-03

### Rollback to JSON (If Needed)
```bash
python rollback_to_json.py
```
- Restores original JSON-based system
- Keeps database backup as `soc_dashboard.db.backup`
- Reverts backend to JSON mode

## 🔮 Future Enhancements

- [x] SQLite database for historical data
- [x] Timeline filtering (7/30/60/90/all days)
- [x] Hourly automated refresh
- [x] Real MTTD/MTTR calculations
- [x] Entity extraction and tracking
- [ ] Real-time data refresh (WebSocket integration)
- [ ] Multi-workspace support
- [ ] Export incident reports to PDF/Excel
- [ ] Email/Teams notifications for critical alerts
- [ ] Role-based access control (RBAC)
- [ ] Custom KQL query builder
- [ ] Incident response workflow automation
- [ ] Advanced correlation rules

## 📝 Development

```bash
# Start backend in debug mode (auto-reload enabled)
python dashboard_backend.py
# Server reloads automatically when Python files change

# Fetch fresh data while server is running
python fetch_live_data.py
python append_data.py

# Test date filtering
# Open http://localhost:5000 and click 7d, 30d, 60d, 90d, All buttons

# Check database stats
python -c "from database import get_database_stats; print(get_database_stats())"
```

## 🏗️ Architecture

```
┌─────────────────┐
│    Browser      │
│  (Dashboard)    │ ← Auto-refresh every 60 min
└────────┬────────┘
         │ HTTP GET with ?days=30
         ▼
┌─────────────────┐
│  Flask Server   │
│  (Port 5000)    │ ← API with date filtering
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ soc_dashboard.db│ ← SQLite with indexed queries
│  • 100 incidents│
│  • 316 alerts   │
│  • 191 entities │
└────────┬────────┘
         ▲
         │
┌────────┴────────┐
│ hourly_refresh  │ ← Runs every hour
│     .py         │
└────────┬────────┘
         │
         ├─► Microsoft Defender (MCP)
         ├─► Microsoft Sentinel (MCP)
         ├─► Microsoft Graph API
         └─► Threat Intel APIs (VT, Talos, AbuseIPDB)
```

## 🤝 Contributing

This is a live SOC dashboard project. Contributions welcome for:
- Additional threat intelligence sources
- Advanced KQL queries for Sentinel
- Custom visualization components
- Performance optimizations
- Security enhancements
