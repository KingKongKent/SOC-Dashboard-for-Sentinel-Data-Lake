"""
IOC Upload Engine for SOC Dashboard
Uploads threat intelligence indicators to Microsoft Sentinel via the REST API.
Supports single IOC, bulk CSV, and open-source feed ingestion.
"""

import csv
import hashlib
import io
import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from config_manager import get_config, set_config

log = logging.getLogger(__name__)

# ── ARM Token Cache ─────────────────────────────────────────────────────────

_token_cache: dict = {}

SENTINEL_API_VERSION = '2024-03-01'

# Default delay between bulk API calls (seconds) — avoids ARM throttling
BULK_DELAY_SECONDS = 0.1


def _get_arm_token() -> str:
    """Acquire a client-credentials token for Azure Resource Manager."""
    cached = _token_cache.get('arm')
    if cached and cached['expires_at'] > time.time() + 60:
        return cached['access_token']

    tenant_id = get_config('TENANT_ID')
    client_id = get_config('CLIENT_ID')
    client_secret = get_config('CLIENT_SECRET')
    if not all([tenant_id, client_id, client_secret]):
        raise RuntimeError('Missing TENANT_ID, CLIENT_ID, or CLIENT_SECRET in config')

    token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
    resp = requests.post(token_url, data={
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://management.azure.com/.default',
        'grant_type': 'client_credentials',
    }, timeout=15)

    if not resp.ok:
        raise RuntimeError(f'ARM token request failed: HTTP {resp.status_code}')

    data = resp.json()
    _token_cache['arm'] = {
        'access_token': data['access_token'],
        'expires_at': time.time() + data.get('expires_in', 3600),
    }
    return data['access_token']


# ── Sentinel Resource Auto-Discovery ────────────────────────────────────────

def _discover_sentinel_resource() -> Tuple[str, str]:
    """Discover Azure subscription ID and resource group for the Sentinel workspace.

    Uses Azure Resource Graph to find the workspace by its customer ID (GUID).
    Caches discovered values in config DB for subsequent calls.
    Falls back to AZURE_SUBSCRIPTION_ID / AZURE_RESOURCE_GROUP config if set.
    """
    # 1. Check if already cached in config
    sub = get_config('AZURE_SUBSCRIPTION_ID')
    rg = get_config('AZURE_RESOURCE_GROUP')
    if sub and rg:
        return sub, rg

    workspace_id = get_config('SENTINEL_WORKSPACE_ID')
    if not workspace_id:
        raise RuntimeError('SENTINEL_WORKSPACE_ID must be set to auto-discover Azure resource info')

    token = _get_arm_token()
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

    # 2. Try Azure Resource Graph query (single POST, works across all subscriptions)
    try:
        graph_url = 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01'
        query = (
            "resources "
            "| where type == 'microsoft.operationalinsights/workspaces' "
            f"| where properties.customerId == '{workspace_id}'"
        )
        resp = requests.post(graph_url, json={'query': query}, headers=headers, timeout=30)
        if resp.ok:
            data = resp.json()
            rg_data = data.get('data', data)  # top-level or nested
            # Handle both table format (rows+columns) and object array format
            resource_id = ''
            if isinstance(rg_data, list) and rg_data:
                # Object array format: list of dicts with 'id' key
                resource_id = rg_data[0].get('id', '')
            elif isinstance(rg_data, dict):
                rows = rg_data.get('rows') or []
                columns = rg_data.get('columns') or []
                if rows and columns:
                    col_names = [c.get('name', c) if isinstance(c, dict) else str(c) for c in columns]
                    row = dict(zip(col_names, rows[0]))
                    resource_id = row.get('id', '')
            if resource_id:
                # Parse: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
                parts = resource_id.split('/')
                if len(parts) >= 5:
                    sub = parts[2]
                    rg = parts[4]
                    set_config('AZURE_SUBSCRIPTION_ID', sub)
                    set_config('AZURE_RESOURCE_GROUP', rg)
                    log.info('✅ Auto-discovered Sentinel resource: sub=%s, rg=%s', sub, rg)
                    return sub, rg
    except Exception as e:
        log.warning('Resource Graph query failed, trying subscription enumeration: %s', e)

    # 3. Fallback: enumerate subscriptions and search for the workspace
    try:
        subs_resp = requests.get(
            'https://management.azure.com/subscriptions?api-version=2020-01-01',
            headers=headers, timeout=30
        )
        if subs_resp.ok:
            for s in subs_resp.json().get('value', []):
                sid = s['subscriptionId']
                ws_url = (
                    f'https://management.azure.com/subscriptions/{sid}'
                    f'/providers/Microsoft.OperationalInsights/workspaces'
                    f'?api-version=2021-06-01'
                )
                ws_resp = requests.get(ws_url, headers=headers, timeout=30)
                if not ws_resp.ok:
                    continue
                for ws in ws_resp.json().get('value', []):
                    if ws.get('properties', {}).get('customerId') == workspace_id:
                        rid = ws.get('id', '')
                        parts = rid.split('/')
                        if len(parts) >= 5:
                            sub = parts[2]
                            rg = parts[4]
                            set_config('AZURE_SUBSCRIPTION_ID', sub)
                            set_config('AZURE_RESOURCE_GROUP', rg)
                            log.info('✅ Auto-discovered Sentinel resource (enum): sub=%s, rg=%s', sub, rg)
                            return sub, rg
    except Exception as e:
        log.warning('Subscription enumeration failed: %s', e)

    raise RuntimeError(
        'Could not auto-discover Azure subscription/resource group for workspace '
        f'{workspace_id}. Set AZURE_SUBSCRIPTION_ID and AZURE_RESOURCE_GROUP in .env.'
    )


# ── Sentinel REST API URL Builder ───────────────────────────────────────────

def _sentinel_ti_url() -> str:
    """Build the Sentinel TI createIndicator URL from config."""
    sub, rg = _discover_sentinel_resource()
    ws = get_config('SENTINEL_WORKSPACE_NAME')
    if not ws:
        raise RuntimeError('SENTINEL_WORKSPACE_NAME must be configured')
    return (
        f'https://management.azure.com/subscriptions/{sub}'
        f'/resourceGroups/{rg}'
        f'/providers/Microsoft.OperationalInsights/workspaces/{ws}'
        f'/providers/Microsoft.SecurityInsights/threatIntelligence/main'
        f'/createIndicator?api-version={SENTINEL_API_VERSION}'
    )


# ── Input Validation ────────────────────────────────────────────────────────

_IPV4_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)
_IPV6_RE = re.compile(r'^[0-9a-fA-F:]{2,39}$')
_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)
_MD5_RE = re.compile(r'^[0-9a-fA-F]{32}$')
_SHA1_RE = re.compile(r'^[0-9a-fA-F]{40}$')
_SHA256_RE = re.compile(r'^[0-9a-fA-F]{64}$')

# Allowed IOC types → (STIX object type, regex or callable)
IOC_TYPES = {
    'ipv4-addr': ('ipv4-addr', _IPV4_RE),
    'ipv6-addr': ('ipv6-addr', _IPV6_RE),
    'domain-name': ('domain-name', _DOMAIN_RE),
    'url': ('url', None),       # validated separately
    'file:md5': ('file', _MD5_RE),
    'file:sha1': ('file', _SHA1_RE),
    'file:sha256': ('file', _SHA256_RE),
}


def validate_ioc(ioc_type: str, value: str) -> Tuple[bool, str]:
    """Validate an IOC type+value pair. Returns (ok, error_message)."""
    value = value.strip()
    if not value:
        return False, 'Value is empty'
    if ioc_type not in IOC_TYPES:
        return False, f'Unknown IOC type: {ioc_type}'

    if ioc_type == 'url':
        if not value.startswith(('http://', 'https://', 'ftp://')):
            return False, 'URL must start with http://, https://, or ftp://'
        if len(value) > 2048:
            return False, 'URL exceeds 2048 characters'
        return True, ''

    _, pattern = IOC_TYPES[ioc_type]
    if pattern and not pattern.match(value):
        return False, f'Invalid format for {ioc_type}'
    return True, ''


# ── STIX Pattern Builder ───────────────────────────────────────────────────

def _build_stix_pattern(ioc_type: str, value: str) -> str:
    """Convert an IOC type+value pair into a STIX 2.x pattern string."""
    # Escape single quotes in value
    safe = value.replace("'", "\\'")

    if ioc_type == 'ipv4-addr':
        return f"[ipv4-addr:value = '{safe}']"
    elif ioc_type == 'ipv6-addr':
        return f"[ipv6-addr:value = '{safe}']"
    elif ioc_type == 'domain-name':
        return f"[domain-name:value = '{safe}']"
    elif ioc_type == 'url':
        return f"[url:value = '{safe}']"
    elif ioc_type == 'file:md5':
        return f"[file:hashes.'MD5' = '{safe}']"
    elif ioc_type == 'file:sha1':
        return f"[file:hashes.'SHA-1' = '{safe}']"
    elif ioc_type == 'file:sha256':
        return f"[file:hashes.'SHA-256' = '{safe}']"
    else:
        raise ValueError(f'Unsupported IOC type: {ioc_type}')


# ── Single IOC Upload ──────────────────────────────────────────────────────

def upload_single_ioc(
    ioc_type: str,
    value: str,
    confidence: int = 50,
    description: str = '',
    tags: Optional[List[str]] = None,
    valid_until: Optional[str] = None,
    source: str = 'SOC Dashboard',
) -> Dict[str, Any]:
    """Upload a single IOC to Sentinel. Returns the API response dict."""
    value = value.strip()
    ok, err = validate_ioc(ioc_type, value)
    if not ok:
        raise ValueError(err)

    confidence = max(0, min(100, int(confidence)))
    pattern = _build_stix_pattern(ioc_type, value)
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')

    if not valid_until:
        valid_until = (datetime.now(timezone.utc) + timedelta(days=30)).strftime(
            '%Y-%m-%dT%H:%M:%S.000Z'
        )

    body: Dict[str, Any] = {
        'kind': 'indicator',
        'properties': {
            'patternType': 'stix',
            'pattern': pattern,
            'confidence': confidence,
            'description': description or f'{ioc_type}: {value}',
            'source': source,
            'validFrom': now,
            'validUntil': valid_until,
            'threatIntelligenceTags': tags or [],
            'displayName': f'{ioc_type}: {value}',
        },
    }

    token = _get_arm_token()
    url = _sentinel_ti_url()

    resp = requests.post(
        url,
        headers={
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        },
        json=body,
        timeout=30,
    )

    if not resp.ok:
        detail = resp.text[:500] if resp.text else f'HTTP {resp.status_code}'
        log.error('Sentinel TI upload failed: %s', detail)
        raise RuntimeError(f'Sentinel API error: HTTP {resp.status_code}')

    return resp.json()


# ── Bulk IOC Upload ─────────────────────────────────────────────────────────

def upload_bulk_iocs(
    iocs: List[Dict[str, Any]],
    delay: float = BULK_DELAY_SECONDS,
    source: str = 'SOC Dashboard',
) -> Dict[str, Any]:
    """Upload multiple IOCs. Each dict needs: type, value; optional: confidence, description, tags, valid_until.
    Returns {uploaded: int, failed: int, errors: list}."""
    results: Dict[str, Any] = {'uploaded': 0, 'failed': 0, 'errors': []}

    for i, ioc in enumerate(iocs):
        ioc_type = ioc.get('type', '').strip()
        value = ioc.get('value', '').strip()
        if not ioc_type or not value:
            results['failed'] += 1
            results['errors'].append({'row': i + 1, 'error': 'Missing type or value'})
            continue

        try:
            upload_single_ioc(
                ioc_type=ioc_type,
                value=value,
                confidence=int(ioc.get('confidence', 50)),
                description=ioc.get('description', ''),
                tags=ioc.get('tags') if isinstance(ioc.get('tags'), list) else [],
                valid_until=ioc.get('valid_until'),
                source=source,
            )
            results['uploaded'] += 1
        except (ValueError, RuntimeError) as exc:
            results['failed'] += 1
            results['errors'].append({'row': i + 1, 'value': value, 'error': str(exc)})

        if delay > 0 and i < len(iocs) - 1:
            time.sleep(delay)

    log.info(
        'Bulk upload complete: %d uploaded, %d failed',
        results['uploaded'],
        results['failed'],
    )
    return results


# ── CSV Parsing ─────────────────────────────────────────────────────────────

def parse_csv(file_content: str) -> List[Dict[str, Any]]:
    """Parse CSV text into IOC dicts. Expected columns: type,value,confidence,description,tags,valid_until.
    Columns beyond 'type' and 'value' are optional."""
    reader = csv.DictReader(io.StringIO(file_content))
    iocs = []
    for row in reader:
        ioc: Dict[str, Any] = {
            'type': row.get('type', '').strip(),
            'value': row.get('value', '').strip(),
        }
        if not ioc['type'] or not ioc['value']:
            continue
        if 'confidence' in row and row['confidence'].strip():
            try:
                ioc['confidence'] = int(row['confidence'].strip())
            except ValueError:
                pass
        if 'description' in row:
            ioc['description'] = row['description'].strip()
        if 'tags' in row and row['tags'].strip():
            ioc['tags'] = [t.strip() for t in row['tags'].split(';') if t.strip()]
        if 'valid_until' in row and row['valid_until'].strip():
            ioc['valid_until'] = row['valid_until'].strip()
        iocs.append(ioc)
    return iocs


# ── Feed Fetch & Parse ──────────────────────────────────────────────────────

# Built-in feed presets (name → config dict)
FEED_PRESETS: Dict[str, Dict[str, Any]] = {
    'abuse.ch URLhaus': {
        'url': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
        'format': 'urlhaus_csv',
        'ioc_type_default': 'url',
        'poll_interval_hours': 4,
    },
    'abuse.ch ThreatFox': {
        'url': 'https://threatfox.abuse.ch/export/csv/recent/',
        'format': 'threatfox_csv',
        'ioc_type_default': 'url',
        'poll_interval_hours': 6,
    },
    'Feodo Tracker C2 IPs': {
        'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
        'format': 'feodo_csv',
        'ioc_type_default': 'ipv4-addr',
        'poll_interval_hours': 6,
    },
    'OpenPhish': {
        'url': 'https://openphish.com/feed.txt',
        'format': 'plaintext',
        'ioc_type_default': 'url',
        'poll_interval_hours': 12,
    },
    'IPsum (Level 3+)': {
        'url': 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
        'format': 'ipsum',
        'ioc_type_default': 'ipv4-addr',
        'poll_interval_hours': 24,
    },
}


def _parse_plaintext_feed(text: str, ioc_type: str) -> List[Dict[str, str]]:
    """Parse a plain-text feed (one IOC per line, # comments)."""
    iocs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        iocs.append({'type': ioc_type, 'value': line})
    return iocs


def _parse_urlhaus_csv(text: str) -> List[Dict[str, str]]:
    """Parse URLhaus CSV (skip comment header lines starting with #)."""
    lines = [l for l in text.splitlines() if not l.startswith('#')]
    iocs = []
    reader = csv.reader(io.StringIO('\n'.join(lines)))
    for row in reader:
        # URLhaus CSV: id, dateadded, url, url_status, ...
        if len(row) >= 3 and row[2].startswith('http'):
            iocs.append({'type': 'url', 'value': row[2].strip()})
    return iocs


def _parse_threatfox_csv(text: str) -> List[Dict[str, str]]:
    """Parse ThreatFox CSV export."""
    lines = [l for l in text.splitlines() if not l.startswith('#')]
    iocs = []
    reader = csv.reader(io.StringIO('\n'.join(lines)))
    for row in reader:
        # ThreatFox CSV: date, ioc_id, ioc_type, ioc_value, ...
        if len(row) >= 4:
            tf_type = row[2].strip().strip('"')
            value = row[3].strip().strip('"')
            if 'ip:port' in tf_type.lower():
                # Strip port for IOC — upload just the IP
                value = value.split(':')[0]
                iocs.append({'type': 'ipv4-addr', 'value': value})
            elif 'domain' in tf_type.lower():
                iocs.append({'type': 'domain-name', 'value': value})
            elif 'url' in tf_type.lower():
                iocs.append({'type': 'url', 'value': value})
            elif 'md5' in tf_type.lower():
                iocs.append({'type': 'file:md5', 'value': value})
            elif 'sha256' in tf_type.lower():
                iocs.append({'type': 'file:sha256', 'value': value})
    return iocs


def _parse_feodo_csv(text: str) -> List[Dict[str, str]]:
    """Parse Feodo Tracker C2 IP blocklist CSV."""
    lines = [l for l in text.splitlines() if not l.startswith('#')]
    iocs = []
    reader = csv.reader(io.StringIO('\n'.join(lines)))
    for row in reader:
        # Feodo CSV: first_seen, dst_ip, dst_port, ...
        if len(row) >= 2 and _IPV4_RE.match(row[1].strip()):
            iocs.append({'type': 'ipv4-addr', 'value': row[1].strip()})
    return iocs


def _parse_ipsum(text: str) -> List[Dict[str, str]]:
    """Parse IPsum aggregated blocklist (IP<tab>score). Keep score >= 3."""
    iocs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('\t')
        if len(parts) >= 2:
            try:
                score = int(parts[1])
            except ValueError:
                continue
            if score >= 3 and _IPV4_RE.match(parts[0]):
                iocs.append({'type': 'ipv4-addr', 'value': parts[0]})
    return iocs


def _parse_stix_bundle(text: str) -> List[Dict[str, str]]:
    """Parse a STIX 2.x JSON bundle and extract indicators."""
    try:
        bundle = json.loads(text)
    except json.JSONDecodeError:
        return []
    iocs = []
    objects = bundle.get('objects', [])
    for obj in objects:
        if obj.get('type') != 'indicator':
            continue
        pattern = obj.get('pattern', '')
        # Try to extract type and value from common STIX patterns
        m = re.match(r"\[(\S+):value\s*=\s*'([^']+)'\]", pattern)
        if m:
            stix_type, value = m.group(1), m.group(2)
            type_map = {
                'ipv4-addr': 'ipv4-addr',
                'ipv6-addr': 'ipv6-addr',
                'domain-name': 'domain-name',
                'url': 'url',
            }
            if stix_type in type_map:
                iocs.append({'type': type_map[stix_type], 'value': value})
        # File hash patterns
        m_hash = re.match(r"\[file:hashes\.'([^']+)'\s*=\s*'([^']+)'\]", pattern)
        if m_hash:
            hash_type, value = m_hash.group(1), m_hash.group(2)
            hash_map = {'MD5': 'file:md5', 'SHA-1': 'file:sha1', 'SHA-256': 'file:sha256'}
            if hash_type in hash_map:
                iocs.append({'type': hash_map[hash_type], 'value': value})
    return iocs


FEED_PARSERS = {
    'plaintext': _parse_plaintext_feed,
    'urlhaus_csv': _parse_urlhaus_csv,
    'threatfox_csv': _parse_threatfox_csv,
    'feodo_csv': _parse_feodo_csv,
    'ipsum': _parse_ipsum,
    'stix2': _parse_stix_bundle,
    'csv': None,  # uses generic parse_csv()
}


def fetch_feed(url: str, feed_format: str, ioc_type_default: str = 'ipv4-addr') -> List[Dict[str, str]]:
    """Fetch a feed URL and parse its content into IOC dicts."""
    resp = requests.get(url, timeout=60, headers={'User-Agent': 'SOC-Dashboard/1.0'})
    resp.raise_for_status()
    text = resp.text

    if feed_format == 'plaintext':
        return _parse_plaintext_feed(text, ioc_type_default)
    elif feed_format in FEED_PARSERS and FEED_PARSERS[feed_format] is not None:
        return FEED_PARSERS[feed_format](text)
    elif feed_format == 'csv':
        return parse_csv(text)
    elif feed_format == 'stix2':
        return _parse_stix_bundle(text)
    else:
        log.warning('Unknown feed format %r, trying plaintext', feed_format)
        return _parse_plaintext_feed(text, ioc_type_default)


# ── Deduplication Helper ────────────────────────────────────────────────────

def compute_ioc_hash(ioc_type: str, value: str) -> str:
    """Compute a stable hash for deduplication."""
    return hashlib.sha256(f'{ioc_type}:{value.lower().strip()}'.encode()).hexdigest()


def deduplicate_iocs(
    iocs: List[Dict[str, str]], uploaded_hashes: set
) -> List[Dict[str, str]]:
    """Filter out IOCs that were already uploaded (by hash)."""
    unique = []
    for ioc in iocs:
        h = compute_ioc_hash(ioc['type'], ioc['value'])
        if h not in uploaded_hashes:
            unique.append(ioc)
            uploaded_hashes.add(h)
    return unique


# ── Feed Poll Orchestrator ──────────────────────────────────────────────────

def poll_feed(feed_id: int, url: str, feed_format: str, ioc_type_default: str = 'ipv4-addr',
              source: str = '') -> Dict[str, Any]:
    """Fetch a feed, deduplicate, upload new IOCs to Sentinel, and update poll timestamp.
    Returns upload summary."""
    from database import get_uploaded_ioc_hashes, record_uploaded_iocs, update_feed_last_poll

    log.info('Polling feed #%d: %s', feed_id, url)
    try:
        iocs = fetch_feed(url, feed_format, ioc_type_default)
    except Exception as exc:
        log.error('Feed fetch failed for #%d: %s', feed_id, exc)
        return {'uploaded': 0, 'failed': 0, 'errors': [str(exc)], 'total_fetched': 0}

    # Deduplicate against previously uploaded IOCs
    existing_hashes = get_uploaded_ioc_hashes()
    new_iocs = deduplicate_iocs(iocs, existing_hashes)

    if not new_iocs:
        update_feed_last_poll(feed_id)
        return {'uploaded': 0, 'failed': 0, 'errors': [], 'total_fetched': len(iocs), 'new': 0}

    result = upload_bulk_iocs(new_iocs, source=source or f'Feed #{feed_id}')

    # Record successfully uploaded IOCs for future dedup
    uploaded_items = []
    error_values = {e.get('value', '') for e in result.get('errors', [])}
    for ioc in new_iocs:
        if ioc['value'] not in error_values:
            uploaded_items.append((ioc['type'], ioc['value']))
    record_uploaded_iocs(uploaded_items)
    update_feed_last_poll(feed_id)

    result['total_fetched'] = len(iocs)
    result['new'] = len(new_iocs)
    return result
