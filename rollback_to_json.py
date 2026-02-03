"""
Rollback Script - Restore JSON-based system if database causes issues
Run this if you need to revert to the original JSON-based system
"""

import os
import shutil
from datetime import datetime

def rollback_to_json():
    """Restore backup files and remove database"""
    
    print("\n" + "="*60)
    print("⏮️  SOC Dashboard: Rolling Back to JSON System")
    print("="*60 + "\n")
    
    backup_files = {
        'fetch_live_data.py.backup': 'fetch_live_data.py',
        'dashboard_backend.py.backup': 'dashboard_backend.py',
        'dashboard_data.json.backup': 'dashboard_data.json'
    }
    
    # Check if backups exist
    missing_backups = []
    for backup_file in backup_files.keys():
        if not os.path.exists(backup_file):
            missing_backups.append(backup_file)
    
    if missing_backups:
        print("❌ Error: Missing backup files:")
        for f in missing_backups:
            print(f"   • {f}")
        print("\n⚠️  Cannot perform rollback without all backup files!")
        return False
    
    # Create a backup of the database before removing it
    if os.path.exists('soc_dashboard.db'):
        db_backup = f'soc_dashboard.db.before_rollback_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
        shutil.copy2('soc_dashboard.db', db_backup)
        print(f"✅ Created database backup: {db_backup}")
    
    # Restore files from backup
    print("\n1️⃣  Restoring original files from backup...")
    for backup_file, original_file in backup_files.items():
        try:
            # Backup current file before overwriting
            if os.path.exists(original_file):
                temp_backup = f"{original_file}.temp_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                shutil.copy2(original_file, temp_backup)
                print(f"   📦 Backed up current {original_file} to {temp_backup}")
            
            # Restore from backup
            shutil.copy2(backup_file, original_file)
            print(f"   ✅ Restored {original_file}")
        except Exception as e:
            print(f"   ❌ Error restoring {original_file}: {e}")
            return False
    
    print("\n2️⃣  Rollback completed successfully!")
    print("\n📋 What was done:")
    print("   • Restored fetch_live_data.py (original version)")
    print("   • Restored dashboard_backend.py (original version)")
    print("   • Restored dashboard_data.json (original data)")
    print("   • Kept database backup (for safety)")
    
    print("\n💡 Next steps:")
    print("   1. Restart the backend: python dashboard_backend.py")
    print("   2. Dashboard will use JSON file (old system)")
    print("   3. To regenerate data: python fetch_live_data.py")
    
    print("\n⚠️  Note: New database files were NOT deleted")
    print("   • Keep database.py, migrate_json_to_db.py, append_data.py")
    print("   • You can retry the database migration later")
    
    print("\n" + "="*60)
    print("✅ Rollback Complete - System restored to JSON mode")
    print("="*60 + "\n")
    
    return True

if __name__ == '__main__':
    print("\n⚠️  WARNING: This will restore your system to JSON-based mode")
    print("   Current database changes will be preserved as backup\n")
    
    response = input("Do you want to proceed with rollback? (yes/no): ").strip().lower()
    
    if response in ['yes', 'y']:
        success = rollback_to_json()
        if success:
            print("\n✅ You can now restart your dashboard with the original system")
        else:
            print("\n❌ Rollback failed. Check error messages above.")
    else:
        print("\n❌ Rollback cancelled")
