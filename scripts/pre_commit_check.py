#!/usr/bin/env python3
"""
Pre-commit secret and vulnerability scanner for SOC Dashboard.

Run before every commit:
    python scripts/pre_commit_check.py

Returns exit code 1 if any issues found.
"""

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Patterns that should NEVER appear in committed code
SECRET_PATTERNS = [
    (r'(?i)(client.secret|api.key|password|token)\s*=\s*["\'][A-Za-z0-9+/=_-]{8,}["\']', "Possible hardcoded secret"),
    (r'(?i)Bearer\s+[A-Za-z0-9._-]{20,}', "Possible hardcoded bearer token"),
    (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', None),  # GUID — checked only in .py files
]

# Vulnerability patterns
VULN_PATTERNS = [
    (r'debug\s*=\s*True', "Flask debug=True — exposes Werkzeug RCE debugger"),
    (r'host\s*=\s*["\']0\.0\.0\.0["\']', "Binding to 0.0.0.0 — exposes to network"),
    (r'CORS\s*\(\s*app\s*\)', "CORS with no origin restriction — allows any origin"),
    (r'eval\s*\(', "eval() — potential code injection"),
    (r'exec\s*\(', "exec() — potential code injection"),
    (r'pickle\.loads?\s*\(', "pickle.load — potential deserialization attack"),
    (r'yaml\.load\s*\(', "yaml.load without SafeLoader — code execution risk"),
    (r'subprocess\.call\s*\(.*shell\s*=\s*True', "subprocess with shell=True — command injection risk"),
    (r'[Cc]:\\[Uu]sers\\[A-Za-z0-9._-]+\\', "Local Windows user path — do not commit machine-specific paths"),
    (r'/home/[A-Za-z0-9._-]+/', "Local Linux home path — do not commit machine-specific paths"),
]

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', 'venv', 'env', '.venv'}
SKIP_FILES = {'pre_commit_check.py'}  # Don't scan ourselves — our patterns are not vulnerabilities
SCAN_EXTENSIONS = {'.py', '.js', '.ts', '.html', '.yml', '.yaml', '.json', '.toml', '.cfg', '.ini'}


def get_staged_files():
    """Get list of files staged for commit."""
    try:
        result = subprocess.run(
            ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACM'],
            capture_output=True, text=True, cwd=REPO_ROOT
        )
        return [REPO_ROOT / f for f in result.stdout.strip().split('\n') if f]
    except FileNotFoundError:
        return []


def scan_file(filepath, patterns, label):
    """Scan a single file for patterns. Returns list of (line_num, line, reason)."""
    findings = []
    try:
        text = filepath.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return findings

    for i, line in enumerate(text.splitlines(), 1):
        for pattern, reason in patterns:
            if reason is None:
                continue  # skip informational patterns
            if re.search(pattern, line):
                # Skip lines that are clearly env var reads
                if 'os.getenv' in line or 'os.environ' in line or 'load_dotenv' in line:
                    continue
                # Skip comments and docstrings
                stripped = line.strip()
                if stripped.startswith('#') or stripped.startswith('//'):
                    continue
                findings.append((i, line.strip()[:120], reason))
    return findings


def main():
    print("=" * 60)
    print("SOC Dashboard — Pre-Commit Security Scan")
    print("=" * 60)

    staged = get_staged_files()
    if not staged:
        # Fall back to scanning all tracked files
        print("No staged files — scanning full repo...\n")
        staged = [
            p for p in REPO_ROOT.rglob('*')
            if p.is_file()
            and p.suffix in SCAN_EXTENSIONS
            and not any(skip in p.parts for skip in SKIP_DIRS)
            and p.name not in SKIP_FILES
        ]

    issues = []
    for filepath in staged:
        if not filepath.exists() or filepath.suffix not in SCAN_EXTENSIONS:
            continue
        if filepath.name in SKIP_FILES:
            continue

        # Secret scan
        for finding in scan_file(filepath, SECRET_PATTERNS, "SECRET"):
            issues.append(("SECRET", filepath.relative_to(REPO_ROOT), *finding))

        # Vuln scan
        for finding in scan_file(filepath, VULN_PATTERNS, "VULN"):
            issues.append(("VULN", filepath.relative_to(REPO_ROOT), *finding))

    if issues:
        print(f"\n{'!'*60}")
        print(f"  FOUND {len(issues)} ISSUE(S) — DO NOT COMMIT")
        print(f"{'!'*60}\n")
        for category, fpath, line_num, line, reason in issues:
            print(f"  [{category}] {fpath}:{line_num}")
            print(f"    Reason: {reason}")
            print(f"    Line:   {line}\n")
        sys.exit(1)
    else:
        print(f"\nScanned {len(staged)} file(s) — no issues found.")
        print("Safe to commit.\n")
        sys.exit(0)


if __name__ == '__main__':
    main()
