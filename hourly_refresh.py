"""
Hourly Data Refresh Script for SOC Dashboard
Automatically fetches and appends new data to the database every hour
"""

import schedule
import time
from datetime import datetime
from append_data import fetch_and_append_new_data

def hourly_refresh_job():
    """
    Job that runs hourly to fetch and append new data
    """
    print("\n" + "="*70)
    print(f"⏰ Hourly Refresh Triggered at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    try:
        result = fetch_and_append_new_data()
        
        print("\n📊 Hourly Refresh Summary:")
        print(f"   • New Incidents Added: {result['new_incidents']}")
        print(f"   • New Alerts Added: {result['new_alerts']}")
        print(f"   • Total in Database: {result['total_incidents']} incidents, {result['total_alerts']} alerts")
        print(f"\n✅ Hourly refresh completed successfully at {datetime.now().strftime('%H:%M:%S')}")
        
    except Exception as e:
        print(f"\n❌ Error during hourly refresh: {e}")
        import traceback
        traceback.print_exc()
    
    print("="*70)
    print(f"⏳ Next refresh scheduled for: {datetime.now().hour + 1:02d}:00")
    print("="*70 + "\n")

def main():
    """
    Main function to start the hourly refresh scheduler
    """
    print("\n" + "="*70)
    print("🚀 SOC Dashboard - Hourly Auto-Refresh Service")
    print("="*70)
    print(f"📅 Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"⏰ Schedule: Every hour on the hour")
    print(f"💾 Database: soc_dashboard.db")
    print("="*70 + "\n")
    
    # Run immediately on start
    print("🔄 Running initial data refresh...")
    hourly_refresh_job()
    
    # Schedule to run every hour
    schedule.every().hour.at(":00").do(hourly_refresh_job)
    
    print("✅ Scheduler is running. Press Ctrl+C to stop.")
    print("💡 This will fetch new data from Defender every hour and append to database\n")
    
    # Keep the script running
    try:
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    except KeyboardInterrupt:
        print("\n\n⏹️  Hourly refresh service stopped by user")
        print(f"📅 Stopped at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == '__main__':
    main()
