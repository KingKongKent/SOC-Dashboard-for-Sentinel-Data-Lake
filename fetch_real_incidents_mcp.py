# -*- coding: utf-8 -*-
"""
Fetch REAL incidents from Microsoft Defender using MCP Triage Tools
This script requires running in a GitHub Copilot agent environment with MCP tools available
"""
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass

def fetch_real_incidents_from_defender():
    """
    Fetch real incidents using MCP Triage tools
    
    This function is designed to be called from a GitHub Copilot agent environment
    where MCP tools are available.
    
    Returns:
        dict: Dashboard data with real incidents, or None if MCP tools not available
    """
    print("\n" + "="*60)
    print("🔍 Fetching REAL Incidents from Microsoft Defender")
    print("="*60)
    print("\n⚠️  This script requires MCP Triage tools to be available")
    print("   Run this from a GitHub Copilot agent environment")
    print("")
    
    try:
        # Import MCP tools dynamically
        # Note: These are only available in MCP agent environments
        print("📡 Attempting to import MCP Triage tools...")
        
        # Try to detect if we're in an MCP environment
        try:
            # In MCP environment, tools are typically available as callable functions
            # For now, we'll provide instructions for manual use
            raise ImportError("Direct import not available - use agent environment")
        
        except ImportError:
            print("\n❌ MCP tools are not directly importable in this environment")
            print("")
            print("🔧 To fetch real incidents, use one of these methods:")
            print("")
            print("METHOD 1: GitHub Copilot Agent")
            print("-" * 60)
            print("1. Open GitHub Copilot Chat in VS Code")
            print("2. Run these commands:")
            print("")
            print("   @agent fetch incidents using mcp_triage_mcp_se_ListIncidents")
            print("   with parameters:")
            print("   - top: 100")
            print("   - includeAlertsData: true")
            print("   - createdAfter: (30 days ago)")
            print("")
            print("3. Save the results to: incidents_real.json")
            print("")
            print("METHOD 2: Use the MCP Tools Directly")
            print("-" * 60)
            print("Call these MCP tools in the agent environment:")
            print("")
            print("Tool: mcp_triage_mcp_se_ListIncidents")
            print("Parameters:")
            print("  {")
            print(f"    \"top\": 100,")
            print(f"    \"includeAlertsData\": true,")
            print(f"    \"createdAfter\": \"{(datetime.now() - timedelta(days=30)).isoformat()}\"")
            print("  }")
            print("")
            print("Tool: mcp_triage_mcp_se_ListAlerts")
            print("Parameters:")
            print("  {")
            print(f"    \"top\": 500,")
            print(f"    \"createdAfter\": \"{(datetime.now() - timedelta(days=30)).isoformat()}\"")
            print("  }")
            print("")
            print("METHOD 3: Use Sample Integration Code")
            print("-" * 60)
            print("See below for Python code that can be run in MCP environment")
            print("")
            
            # Generate sample code that would work in MCP environment
            generate_sample_mcp_code()
            
            return None
            
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return None

def generate_sample_mcp_code():
    """Generate sample code for MCP environment"""
    
    sample_code = '''
# Sample code for MCP environment
# Copy this code and run it in a GitHub Copilot agent context

from datetime import datetime, timedelta
import json

# Calculate date range
end_date = datetime.now()
start_date = end_date - timedelta(days=30)

print(f"Fetching incidents from {start_date.date()} to {end_date.date()}")

# Call MCP tool to list incidents
incidents_result = mcp_triage_mcp_se_ListIncidents(
    top=100,
    includeAlertsData=True,
    createdAfter=start_date.isoformat()
)

# Call MCP tool to list alerts
alerts_result = mcp_triage_mcp_se_ListAlerts(
    top=500,
    createdAfter=start_date.isoformat()
)

# Process and format data
dashboard_data = {
    "timestamp": datetime.now().isoformat(),
    "incidents": [],
    "alerts": []
}

# Format incidents
for incident in incidents_result.get('value', []):
    dashboard_data["incidents"].append({
        "id": incident.get("incidentId") or incident.get("id"),
        "title": incident.get("incidentName") or incident.get("title"),
        "severity": incident.get("severity"),
        "status": incident.get("status"),
        "classification": incident.get("classification"),
        "determination": incident.get("determination"),
        "createdTime": incident.get("createdDateTime") or incident.get("createdTime"),
        "lastUpdateTime": incident.get("lastUpdateDateTime") or incident.get("lastUpdateTime"),
        "assignedTo": incident.get("assignedTo"),
        "tags": incident.get("tags", []),
        "alertCount": len(incident.get("alerts", [])),
        "entities": [
            {
                "type": e.get("entityType") or e.get("type"),
                "name": e.get("name") or e.get("displayName"),
                "verdict": e.get("verdict", "unknown")
            }
            for e in incident.get("entities", [])
        ],
        "mitreTechniques": incident.get("mitreAttackTechniques", []),
        "webUrl": incident.get("incidentWebUrl") or incident.get("webUrl")
    })

# Format alerts
for alert in alerts_result.get('value', []):
    dashboard_data["alerts"].append({
        "id": alert.get("id"),
        "incidentId": alert.get("incidentId"),
        "title": alert.get("title"),
        "severity": alert.get("severity"),
        "category": alert.get("category"),
        "status": alert.get("status"),
        "timestamp": alert.get("createdDateTime") or alert.get("timestamp"),
        "product": alert.get("serviceSource"),
        "detectionSource": alert.get("detectionSource")
    })

# Save to file
print(f"\\nSaving {len(dashboard_data['incidents'])} incidents and {len(dashboard_data['alerts'])} alerts")

with open("incidents_real.json", "w") as f:
    json.dump(dashboard_data, f, indent=2)

print("✅ Real incidents saved to: incidents_real.json")
print("\\n📝 Next steps:")
print("1. Copy incidents_real.json to your dashboard directory")
print("2. Run: python append_data.py")
print("3. Restart dashboard: python dashboard_backend.py")
'''
    
    # Save sample code to file
    sample_file = Path(__file__).parent / "sample_mcp_fetch.py"
    with open(sample_file, 'w', encoding='utf-8') as f:
        f.write(sample_code)
    
    print(f"💾 Sample code saved to: {sample_file}")
    print("")
    print("This sample code can be run in a GitHub Copilot agent environment")
    print("where MCP tools are available.")
    print("")

def load_real_incidents_from_file():
    """
    Load real incidents from a JSON file if available
    This is used after manually fetching data via MCP tools
    """
    incidents_file = Path(__file__).parent / "incidents_real.json"
    
    if incidents_file.exists():
        print(f"\n✅ Found real incidents file: {incidents_file}")
        print("Loading data...")
        
        with open(incidents_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print(f"📊 Loaded:")
        print(f"   • {len(data.get('incidents', []))} incidents")
        print(f"   • {len(data.get('alerts', []))} alerts")
        
        return data
    else:
        print(f"\n⚠️  No real incidents file found: {incidents_file}")
        print("Please fetch incidents using MCP tools first")
        return None

if __name__ == '__main__':
    print("\n" + "="*60)
    print("📡 Microsoft Defender Real Incidents Fetcher")
    print("="*60)
    
    # Try to fetch from MCP
    result = fetch_real_incidents_from_defender()
    
    if result is None:
        # Try to load from file
        print("\n" + "="*60)
        print("📁 Checking for Previously Fetched Data")
        print("="*60)
        
        data = load_real_incidents_from_file()
        
        if data:
            print("\n✅ Real incidents data available")
            print("Run 'python append_data.py' to update database")
        else:
            print("\n⚠️  No real incidents available")
            print("Follow the instructions above to fetch using MCP tools")
    
    print("\n" + "="*60)
    print("Done!")
    print("="*60 + "\n")
