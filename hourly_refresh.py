"""
Hourly Data Refresh Script for SOC Dashboard
Automatically fetches and appends new data to the database.
Refresh interval is configurable via the settings page (REFRESH_INTERVAL_MINUTES).
"""

import schedule
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from append_data import fetch_and_append_new_data

# Maximum time (seconds) to wait for a single fetch cycle before killing it
FETCH_TIMEOUT_SECONDS = 300  # 5 minutes

# Track current interval so we can detect changes
_current_interval = None

def _get_interval_minutes() -> int:
    """Read refresh interval from config DB, fall back to 60."""
    try:
        from config_manager import get_config
        val = get_config('REFRESH_INTERVAL_MINUTES', '60')
        return max(1, int(val))
    except Exception:
        return 60


def _reschedule_if_changed():
    """Re-register the schedule job if the configured interval changed."""
    global _current_interval
    desired = _get_interval_minutes()
    if desired != _current_interval:
        schedule.clear()
        schedule.every(desired).minutes.do(hourly_refresh_job)
        print(f"🔄 Scheduler interval updated: every {desired} minutes")
        _current_interval = desired


def _poll_due_feeds():
    """Check enabled IOC feeds and poll any that are due."""
    try:
        from config_manager import get_config
        val = (get_config('IOC_UPLOAD_ENABLED') or '').strip().lower()
        if val not in ('true', '1', 'yes', 'on'):
            return  # feature disabled

        from database import get_feeds
        feeds = get_feeds(enabled_only=True)
        if not feeds:
            return

        now = datetime.now()
        from ioc_upload import poll_feed
        for feed in feeds:
            last = feed.get('last_poll')
            if last:
                try:
                    last_dt = datetime.fromisoformat(last)
                except (ValueError, TypeError):
                    last_dt = datetime.min
            else:
                last_dt = datetime.min
            interval_hours = feed.get('poll_interval_hours', 24)
            if (now - last_dt).total_seconds() >= interval_hours * 3600:
                print(f"🛡️  Polling feed: {feed['name']} ({feed['url'][:60]})")
                try:
                    result = poll_feed(
                        feed_id=feed['id'],
                        url=feed['url'],
                        feed_format=feed['format'],
                        ioc_type_default=feed.get('ioc_type_default', 'ipv4-addr'),
                        source=f'Feed: {feed["name"]}',
                    )
                    print(f"   ✅ {result.get('uploaded', 0)} new IOCs uploaded, "
                          f"{result.get('failed', 0)} failed")
                except Exception as exc:
                    print(f"   ❌ Feed poll failed: {exc}")
    except ImportError:
        pass  # ioc_upload or database not available
    except Exception as e:
        print(f"⚠️ Feed polling error: {e}")


def hourly_refresh_job():
    """
    Job that runs hourly to fetch and append new data
    """
    print("\n" + "="*70)
    print(f"⏰ Hourly Refresh Triggered at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(fetch_and_append_new_data)
            result = future.result(timeout=FETCH_TIMEOUT_SECONDS)
        
        print("\n📊 Hourly Refresh Summary:")
        print(f"   • New Incidents Added: {result['new_incidents']}")
        print(f"   • New Alerts Added: {result['new_alerts']}")
        print(f"   • Total in Database: {result['total_incidents']} incidents, {result['total_alerts']} alerts")
        print(f"\n✅ Hourly refresh completed successfully at {datetime.now().strftime('%H:%M:%S')}")
        
    except FuturesTimeoutError:
        print(f"\n⚠️ Hourly refresh TIMED OUT after {FETCH_TIMEOUT_SECONDS}s — skipping this cycle")
    except Exception as e:
        print(f"\n❌ Error during hourly refresh: {e}")
        import traceback
        traceback.print_exc()

    # ── IOC Feed Polling ─────────────────────────────
    _poll_due_feeds()
    
    print("="*70)
    print(f"⏳ Next refresh scheduled for: {datetime.now().hour + 1:02d}:00")
    print("="*70 + "\n")

def main():
    """
    Main function to start the hourly refresh scheduler
    """
    interval = _get_interval_minutes()

    print("\n" + "="*70)
    print("🚀 SOC Dashboard - Auto-Refresh Service")
    print("="*70)
    print(f"📅 Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"⏰ Schedule: Every {interval} minutes (configurable via settings)")
    print(f"💾 Database: soc_dashboard.db")
    print("="*70 + "\n")
    
    # Run immediately on start
    print("🔄 Running initial data refresh...")
    hourly_refresh_job()
    
    # Schedule based on configured interval
    _reschedule_if_changed()
    
    print("✅ Scheduler is running. Press Ctrl+C to stop.")
    print(f"💡 Refresh interval: {interval} minutes (change via settings page)\n")
    
    # Keep the script running
    try:
        while True:
            # Check if interval was changed via settings
            _reschedule_if_changed()
            schedule.run_pending()
            time.sleep(30)  # Check every 30 seconds
    except KeyboardInterrupt:
        print("\n\n⏹️  Refresh service stopped by user")
        print(f"📅 Stopped at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == '__main__':
    main()
