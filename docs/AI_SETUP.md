# AI Assistant Setup — Azure AI Foundry / OpenAI Integration

> How to configure the SOC Dashboard AI features: the interactive AI analyst,
> attack story generation, and AI-powered incident enrichment.

---

## Overview

The AI Assistant has two operating modes, selected automatically based on which
configuration keys are present:

| Mode | Config Required | Capabilities |
|------|----------------|--------------|
| **Agent mode** (Foundry Responses API) | `FOUNDRY_PROJECT_ENDPOINT` + `FOUNDRY_DEPLOYMENT` | Full Sentinel MCP tool access — the AI can query Data Lake, triage incidents in Defender XDR, and drill into entities autonomously |
| **Direct completion** (fallback) | `FOUNDRY_ENDPOINT` + `FOUNDRY_DEPLOYMENT` | KQL generation + auto-execution via Log Analytics REST API — no MCP tool access |

Agent mode is preferred. If the agent call fails (e.g., MCP server 401), the
system automatically falls back to direct completion.

---

## Prerequisites

### 1. Azure AI Foundry Project

You need an Azure AI Foundry project with a deployed model (e.g., `gpt-4o`).

1. Go to [Azure AI Foundry](https://ai.azure.com) and create or open a project.
2. Deploy a model (e.g., `gpt-4o`) — note the **deployment name**.
3. Copy the **project endpoint** (format: `https://<resource>.services.ai.azure.com/api/projects/<project-name>`).
4. Copy the **resource endpoint** (format: `https://<resource>.openai.azure.com`).

### 2. Entra ID App Registration

The dashboard already uses an Entra ID app registration for user login. The AI
features reuse the same `CLIENT_ID` / `CLIENT_SECRET` / `TENANT_ID` credentials
as a service principal for:

- Acquiring Azure Cognitive Services tokens (scope: `https://cognitiveservices.azure.com/.default`)
- Authenticating to the Foundry project via `ClientSecretCredential`
- Acquiring Sentinel MCP tokens (scope: `4500ebfb-89b6-4b14-a480-7f749797bfcd/.default`)

#### Required API Permissions

Add these **application** permissions to the app registration (in addition to
existing delegated permissions for user login):

| API | Permission | Type | Purpose |
|-----|-----------|------|---------|
| Azure AI Services (Cognitive Services) | `Cognitive Services OpenAI User` | Application | Direct completion fallback |
| Microsoft Sentinel Platform | `4500ebfb-89b6-4b14-a480-7f749797bfcd/.default` | Application | Data Lake MCP server (SP token) |

For the **Triage MCP server** (Defender XDR entity drill-down), the dashboard
uses **delegated** tokens acquired from the logged-in user's session. Add this
delegated permission:

| API | Permission | Type | Purpose |
|-----|-----------|------|---------|
| Microsoft Defender MCP | `MCP.Read.All` | Delegated | Triage MCP server (user token) |

> **Note:** After adding permissions, grant admin consent in the Azure portal.

#### Foundry RBAC

The service principal needs a role assignment on the AI Foundry project:

```
Azure AI Developer
```

Assign it at the AI Foundry resource or resource-group scope.

### 3. Python Dependencies

These packages (already in `requirements.txt`) are required:

```
openai>=1.30
azure-ai-projects>=2.0
azure-identity>=1.16
```

Install with:

```bash
pip install -r requirements.txt
```

---

## Configuration

All AI settings are configured via environment variables (`.env` file) or
through the dashboard Settings page (stored encrypted in SQLite).

### Environment Variables

Add these to your `.env` file:

```bash
# ── AI & Data Lake (Azure AI Foundry) ──

# Azure OpenAI resource endpoint (used for direct completion fallback)
FOUNDRY_ENDPOINT=https://your-resource.openai.azure.com

# Model deployment name (e.g. gpt-4o)
FOUNDRY_DEPLOYMENT=gpt-4o

# AI Foundry project endpoint (enables agent mode with Sentinel MCP tools)
FOUNDRY_PROJECT_ENDPOINT=https://your-resource.services.ai.azure.com/api/projects/your-project

# Optional: named agent in Foundry project (leave empty to use default)
FOUNDRY_AGENT_NAME=

# ── Feature Toggle ──
AI_ASSISTANT_ENABLED=true
```

### Settings Page (Runtime)

All four `FOUNDRY_*` keys and `AI_ASSISTANT_ENABLED` are configurable from the
admin Settings overlay in the dashboard UI (requires the `Admin` app role).
Values set via Settings take precedence over `.env`.

### Minimum Viable Config

| Goal | Required Keys |
|------|--------------|
| Direct completion only | `FOUNDRY_ENDPOINT`, `FOUNDRY_DEPLOYMENT`, `AI_ASSISTANT_ENABLED=true` |
| Agent mode (full MCP) | `FOUNDRY_PROJECT_ENDPOINT`, `FOUNDRY_DEPLOYMENT`, `AI_ASSISTANT_ENABLED=true` |
| Both (agent + fallback) | All four keys + toggle |

---

## How It Works

### Agent Mode (Responses API)

```
User question
  → POST /api/sentinel/ai
    → ask_agent()
      → ClientSecretCredential (TENANT_ID, CLIENT_ID, CLIENT_SECRET)
      → AIProjectClient(project_endpoint, credential)
      → oai.responses.create(model, instructions, input, tools=[MCP servers])
        ├── Data Lake MCP (SP token) — KQL over full Sentinel history
        └── Triage MCP (user delegated token) — Defender XDR entity drill-down
      → Parse answer + KQL blocks
```

The agent has access to two MCP tool servers:

| Server | URL | Auth | Capabilities |
|--------|-----|------|-------------|
| Data Lake | `sentinel.microsoft.com/mcp/data-exploration` | Service principal token | `query_lake`, `search_tables`, `list_sentinel_workspaces` |
| Triage | `sentinel.microsoft.com/mcp/triage` | User delegated token | `ListIncidents`, `GetIncidentById`, `RunAdvancedHuntingQuery`, `GetDefenderMachine`, and 20+ Defender XDR tools |

If the Triage MCP server returns 401 (no delegated token), the agent retries
with Data Lake tools only. If both fail, it retries with no tools (pure LLM).

### Direct Completion Fallback

```
User question
  → ask_assistant()
    → AzureOpenAI(azure_endpoint=FOUNDRY_ENDPOINT, azure_ad_token_provider)
    → chat.completions.create(model, messages)
    → Parse KQL from ```kql blocks
    → Auto-execute KQL via Log Analytics REST API (sentinel_kql.py)
```

The direct client authenticates via `azure_ad_token_provider` callback, which
acquires a Cognitive Services token using the same SP credentials.

---

## API Endpoints

All endpoints require `@require_login`. The feature toggle
`AI_ASSISTANT_ENABLED` must be `true`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/sentinel/ai` | POST | Ask a freeform security question. Body: `{"question": "...", "history": [...]}` |
| `/api/incidents/<id>/attack-story` | POST | Generate (or retrieve cached) AI attack story for an incident |
| `/api/incidents/<id>/ai-enrich` | POST | AI-analyse an incident and post the analysis as a Sentinel comment |

---

## Verification

### 1. Check Config is Set

Open the dashboard Settings page (admin) and confirm all four Foundry fields
are populated (fields with values show a lock icon).

Or from the server host:

```bash
python -c "from config_manager import get_config; print(get_config('FOUNDRY_PROJECT_ENDPOINT'))"
```

### 2. Test Direct Completion

```bash
curl -s -X POST https://your-domain.com/api/sentinel/ai \
  -H "Content-Type: application/json" \
  -d '{"question": "Show me the top 5 security incidents by severity from the last 7 days"}' \
  --cookie "session=<your-session-cookie>"
```

Expected response: JSON with `answer` (markdown), `kql` (extracted query), and
`results` (query output).

### 3. Test Agent Mode

Same endpoint — if `FOUNDRY_PROJECT_ENDPOINT` is configured, it automatically
uses agent mode. Check server logs for:

```
INFO  Agent response items: ['tool_call', 'message']
INFO  MCP tools called: ['query_lake']
```

### 4. Verify MCP Connectivity

Check logs for 401 fallback messages:

- `Triage MCP 401 — retrying with Data Lake tools only` → Triage token issue
- `Data Lake MCP 401 — retrying with Triage tools only` → SP token issue
- `All MCP servers unavailable — retrying agent with no tools` → Both failed

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "AI Assistant not configured" | `FOUNDRY_ENDPOINT` and `FOUNDRY_DEPLOYMENT` both missing | Set them in `.env` or Settings |
| "AI Assistant is disabled" | `AI_ASSISTANT_ENABLED` is `false` or unset | Set to `true` in Settings |
| 401 on Cognitive Services token | SP missing `Cognitive Services OpenAI User` role | Assign role on the AI Foundry resource |
| 401 on Data Lake MCP | SP missing Sentinel platform access | Verify scope consent and SP permissions |
| 401 on Triage MCP | User hasn't consented to `MCP.Read.All` | Clear sessions so users re-consent at next login |
| Agent returns empty answer | Model deployment name mismatch | Verify `FOUNDRY_DEPLOYMENT` matches the exact deployment name in Foundry |
| KQL auto-execute fails | Generated KQL references non-existent tables | Known LLM limitation — the system prompt constrains table names but it's not foolproof |
| `FOUNDRY_PROJECT_ENDPOINT not configured` warning in logs | Agent mode disabled, using direct fallback | Set `FOUNDRY_PROJECT_ENDPOINT` to enable agent mode |
| `AADSTS50011` redirect error after adding scopes | Redirect URI not registered | Add `https://<domain>/auth/callback` in Entra app registration |

---

## Security Notes

- **Credentials are never hardcoded.** All secrets come from `config_manager.get_config()` (encrypted DB) or `os.getenv()`.
- **SP tokens (Data Lake)** are short-lived and acquired per-request. No caching is implemented.
- **User tokens (Triage)** are acquired via MSAL silent token acquisition from the user's session cache.
- **The AI is read-only.** All agent instructions explicitly prohibit data modification. KQL queries are limited by `sentinel_kql.py` safety caps (row limit, timeout).
- **Error messages are generic.** API responses never expose `str(e)` — errors are logged server-side.
