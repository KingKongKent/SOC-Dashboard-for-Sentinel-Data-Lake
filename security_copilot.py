"""
Security Copilot Integration Module for SOC Dashboard
Handles incident enrichment via:
  1. Azure AI Foundry agent (on-demand, reuses ask_agent with Triage MCP tools)
  2. Logic App webhook callbacks (automated, Sentinel-triggered)
"""

import json
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from database import get_enrichment, get_incidents, insert_enrichment
from config_manager import get_config


# ── Prompt Construction ──────────────────────────────────────────────────────

def build_enrichment_prompt(incident: Dict[str, Any]) -> str:
    """Build a structured multi-section enrichment prompt for Security Copilot."""
    incident_id = incident.get('id', 'unknown')
    title = incident.get('title', 'Unknown Incident')
    severity = incident.get('severity', 'unknown')
    status = incident.get('status', 'unknown')
    entities = incident.get('entities', [])
    mitre = incident.get('mitreTechniques', [])

    entity_lines = '\n'.join(
        f'  - {e.get("type", "?")}: {e.get("name", "?")} (verdict: {e.get("verdict", "unknown")})'
        for e in entities[:30]
    )

    prompt = (
        f'Analyse Microsoft Defender incident {incident_id}.\n'
        f'Title: {title}\n'
        f'Severity: {severity}\n'
        f'Status: {status}\n'
    )
    if entity_lines:
        prompt += f'Entities:\n{entity_lines}\n'
    if mitre:
        prompt += f'MITRE Techniques: {", ".join(mitre)}\n'

    prompt += (
        '\nProvide your analysis in the following structured format:\n\n'
        '## RISK SCORE\n'
        '[A single number from 1 to 100, where 1 is lowest risk and 100 is highest]\n\n'
        '## EXECUTIVE SUMMARY\n'
        '[2-3 paragraph analysis of what happened, impact assessment, and threat level]\n\n'
        '## RECOMMENDED ACTIONS\n'
        '1. [First recommended response action]\n'
        '2. [Second recommended response action]\n'
        '...\n\n'
        '## ENTITY REPUTATIONS\n'
        '- [Entity name] ([type]): [reputation assessment and details]\n'
        '...\n'
    )
    return prompt


# ── Response Parsing ─────────────────────────────────────────────────────────

def parse_enrichment_response(response_text: str) -> Dict[str, Any]:
    """Parse a structured enrichment response into components."""
    result: Dict[str, Any] = {
        'risk_score': None,
        'summary': None,
        'recommended_actions': [],
        'entity_reputations': [],
    }

    if not response_text:
        return result

    # Extract RISK SCORE
    score_match = re.search(
        r'##\s*RISK\s*SCORE\s*\n+\s*(\d{1,3})', response_text, re.IGNORECASE
    )
    if score_match:
        score = int(score_match.group(1))
        result['risk_score'] = max(1, min(100, score))

    # Extract EXECUTIVE SUMMARY
    summary_match = re.search(
        r'##\s*EXECUTIVE\s*SUMMARY\s*\n+(.*?)(?=\n##\s|\Z)',
        response_text, re.IGNORECASE | re.DOTALL,
    )
    if summary_match:
        result['summary'] = summary_match.group(1).strip()

    # Extract RECOMMENDED ACTIONS
    actions_match = re.search(
        r'##\s*RECOMMENDED\s*ACTIONS\s*\n+(.*?)(?=\n##\s|\Z)',
        response_text, re.IGNORECASE | re.DOTALL,
    )
    if actions_match:
        actions_text = actions_match.group(1).strip()
        result['recommended_actions'] = [
            line.strip().lstrip('0123456789.-) ').strip()
            for line in actions_text.split('\n')
            if line.strip() and not line.strip().startswith('...')
        ]

    # Extract ENTITY REPUTATIONS
    reputations_match = re.search(
        r'##\s*ENTITY\s*REPUTATIONS?\s*\n+(.*?)(?=\n##\s|\Z)',
        response_text, re.IGNORECASE | re.DOTALL,
    )
    if reputations_match:
        rep_text = reputations_match.group(1).strip()
        for line in rep_text.split('\n'):
            line = line.strip().lstrip('- ').strip()
            if not line or line.startswith('...'):
                continue
            # Try to parse "name (type): details"
            m = re.match(r'^(.+?)\s*\(([^)]+)\)\s*:\s*(.+)$', line)
            if m:
                result['entity_reputations'].append({
                    'entity_name': m.group(1).strip(),
                    'entity_type': m.group(2).strip(),
                    'details': m.group(3).strip(),
                })
            else:
                result['entity_reputations'].append({
                    'entity_name': line,
                    'entity_type': 'unknown',
                    'details': '',
                })

    return result


# ── Enrichment via Foundry Agent ─────────────────────────────────────────────

def enrich_via_foundry(incident_id: str) -> Dict[str, Any]:
    """Enrich an incident using the Foundry agent (on-demand path).

    Returns dict with keys: success, risk_score, summary, error.
    """
    from database import get_incidents as _get_incidents

    # Skip if recent enrichment exists (< 1 hour old)
    existing = get_enrichment(incident_id)
    if existing:
        created = existing.get('created_at', '')
        try:
            created_dt = datetime.fromisoformat(created)
            if datetime.now() - created_dt < timedelta(hours=1):
                return {
                    'success': True,
                    'risk_score': existing.get('risk_score'),
                    'summary': existing.get('summary'),
                    'recommended_actions': existing.get('recommended_actions', []),
                    'entity_reputations': existing.get('entity_reputations', []),
                    'cached': True,
                }
        except (ValueError, TypeError):
            pass

    # Look up incident data from DB
    incidents = _get_incidents(days=90)
    incident = next((i for i in incidents if str(i.get('id')) == str(incident_id)), None)
    if not incident:
        return {'success': False, 'error': 'Incident not found in database'}

    prompt = build_enrichment_prompt(incident)

    try:
        from ai_assistant import ask_agent
        from auth import get_user_sentinel_token, get_user_triage_token
        user_token = get_user_sentinel_token()
        triage_token = get_user_triage_token()
        result = ask_agent(prompt, user_token=user_token, triage_token=triage_token)
        answer = result.get('answer', '')
    except Exception as e:
        print(f"❌ Foundry enrichment failed for {incident_id}: {e}")
        return {'success': False, 'error': 'AI enrichment request failed'}

    if not answer:
        return {'success': False, 'error': 'AI returned an empty response'}

    parsed = parse_enrichment_response(answer)
    model = get_config('FOUNDRY_DEPLOYMENT') or 'unknown'

    insert_enrichment(
        incident_id=str(incident_id),
        source='foundry_agent',
        risk_score=parsed['risk_score'],
        summary=parsed['summary'],
        recommended_actions=parsed['recommended_actions'],
        entity_reputations=parsed['entity_reputations'],
        session_id=None,
        model=model,
    )

    return {
        'success': True,
        'risk_score': parsed['risk_score'],
        'summary': parsed['summary'],
        'recommended_actions': parsed['recommended_actions'],
        'entity_reputations': parsed['entity_reputations'],
        'cached': False,
    }


# ── Webhook Payload Processing (Logic App callbacks) ─────────────────────────

def process_webhook_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and store an enrichment from a Logic App webhook callback.

    Expected payload:
      { incident_id, copilot_response, session_id? }
    Returns dict with keys: success, error.
    """
    incident_id = payload.get('incident_id')
    response_text = payload.get('copilot_response', '')
    session_id = payload.get('session_id')

    if not incident_id:
        return {'success': False, 'error': 'Missing incident_id'}
    if not response_text:
        return {'success': False, 'error': 'Missing copilot_response'}

    parsed = parse_enrichment_response(response_text)

    ok = insert_enrichment(
        incident_id=str(incident_id),
        source='security_copilot',
        risk_score=parsed['risk_score'],
        summary=parsed['summary'],
        recommended_actions=parsed['recommended_actions'],
        entity_reputations=parsed['entity_reputations'],
        session_id=session_id,
        model='security-copilot',
    )

    if ok:
        print(f"✅ Stored Security Copilot enrichment for incident {incident_id}")
        return {'success': True}
    return {'success': False, 'error': 'Database insert failed'}


# ── Batch / Auto-Enrichment Helper ──────────────────────────────────────────

def auto_enrich_new_incidents(incident_ids: List[str]) -> Dict[str, Any]:
    """Enrich a batch of newly inserted incidents via Foundry agent.

    Respects COPILOT_AUTO_ENRICH_MAX_PER_CYCLE config.
    Returns summary dict.
    """
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

    max_per_cycle = 10
    try:
        max_per_cycle = int(get_config('COPILOT_AUTO_ENRICH_MAX_PER_CYCLE', '10') or '10')
    except (TypeError, ValueError):
        pass
    max_per_cycle = max(1, min(50, max_per_cycle))

    to_enrich = incident_ids[:max_per_cycle]
    if not to_enrich:
        return {'enriched': 0, 'failed': 0, 'skipped': len(incident_ids)}

    enriched = 0
    failed = 0

    def _enrich_one(iid: str) -> bool:
        try:
            result = enrich_via_foundry(iid)
            return result.get('success', False)
        except Exception as e:
            print(f"⚠️  Auto-enrich failed for {iid}: {e}")
            return False

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(_enrich_one, iid): iid for iid in to_enrich}
        for future in futures:
            try:
                if future.result(timeout=90):
                    enriched += 1
                else:
                    failed += 1
            except (FutureTimeout, Exception):
                failed += 1

    skipped = len(incident_ids) - len(to_enrich)
    print(f"🤖 Auto-enrichment: {enriched} enriched, {failed} failed, {skipped} skipped (cap: {max_per_cycle})")
    return {'enriched': enriched, 'failed': failed, 'skipped': skipped}
