#!/usr/bin/env python3
import sys, os
sys.path.insert(0, '/opt/soc-dashboard')
os.chdir('/opt/soc-dashboard')
from dotenv import load_dotenv
load_dotenv('/etc/soc-dashboard/.env')
from config_manager import set_config, get_config
set_config('FOUNDRY_DEPLOYMENT', 'gpt-4o')
print(f"FOUNDRY_DEPLOYMENT = {repr(get_config('FOUNDRY_DEPLOYMENT'))}")
print("Done")
