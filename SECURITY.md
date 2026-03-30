# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| main branch (latest) | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in this project:

1. **Do NOT open a public issue.**
2. Email the maintainer directly or use GitHub's private vulnerability reporting.
3. Include: description, reproduction steps, and potential impact.
4. You can expect an initial response within 72 hours.

## Security Practices

- All credentials are loaded from environment variables (`.env`) — never committed.
- SQLite queries use parameterised bindings — no string formatting in SQL.
- Flask debug mode is disabled by default; only enabled via `FLASK_DEBUG=1` env var.
- CORS is restricted to configured origins.
- See [docs/SECURITY_FIXES.md](docs/SECURITY_FIXES.md) for tracked vulnerability patches.
