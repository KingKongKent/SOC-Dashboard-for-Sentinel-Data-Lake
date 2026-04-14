#!/usr/bin/env python3
import sys, os
sys.path.insert(0, '/opt/soc-dashboard')
os.chdir('/opt/soc-dashboard')
from dotenv import load_dotenv
load_dotenv('/etc/soc-dashboard/.env')
from config_manager import get_config
keys = ['FOUNDRY_ENDPOINT','FOUNDRY_DEPLOYMENT','FOUNDRY_PROJECT_ENDPOINT','FOUNDRY_AGENT_NAME','AI_ASSISTANT_ENABLED']
for k in keys:
    print(f"{k} = {repr(get_config(k))}")
