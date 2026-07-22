"""Scanning engine: classic app holes + agent-layer checks."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from .agent import scan_agent_layer
from .detect import detect_stack
from .models import Finding, ScanResult

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "dist", "build",
             ".next", "out", "__pycache__", ".mypy_cache", ".pytest_cache",
             "coverage", ".turbo", "vendor", ".idea", ".tox", ".nox"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip",
            ".gz", ".tar", ".woff", ".woff2", ".ttf", ".mp4", ".mov", ".map"}
MAX_FILE_BYTES = 1_000_000

SECRET_PATTERNS = [
    ("Stripe secret key", re.compile(r"sk_live_[0-9a-zA-Z]{20,}")),
    ("OpenAI / sk- key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Secret assignment", re.compile(
        r"(?i)(?:secret|password|passwd|token|api[_-]?key)\s*[:=]\s*['\"][0-9A-Za-z_\-]{16,}['\"]")),
]
SECRET_ALLOW = re.compile(
    r"(?i)(your[_-]?|example|placeholder|changeme|dummy|sample|xxxx+|<[^>]+>|"
    r"sk_test_|pk_test_|pk_live_|process\.env|import\.meta\.env|os\.environ|getenv)")
PUBLIC_PREFIX = re.compile(
    r"(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_)"
    r"[A-Z0-9_]*(SECRET|PRIVATE|PASSWORD|SERVICE_ROLE|API_KEY|ACCESS_KEY)")
PUBLIC_OK = re.compile(r"(PUBLISHABLE|ANON|_PUBLIC_KEY)")
RISKY_PATTERNS = [
    ("XSS sink (dangerouslySetInnerHTML)", re.compile(r"dangerouslySetInnerHTML")),
    ("Use of eval()", re.compile(r"(?<![A-Za-z_])eval\s*\(")),
    ("Shell execution", re.compile(r"child_process|subprocess\.(?:call|run|Popen)|os\.system")),
    ("NoSQL $where injection", re.compile(r"\$where")),
    ("Open Firebase rule", re.compile(r'"\.(?:read|write)"\s*:\s*true')),
    ("Open Firestore/Storage rule", re.compile(r"allow\s+[a-z, ]+:\s*if\s+true")),
    ("Wildcard CORS", re.compile(r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]|origin:\s*['\"]\*['\"]")),
]
# Deliberately line-scoped heuristic; cross-line data flow belongs in the
# investigation agent rather than pretending this regex is a full taint engine.
SQL_INJECTION = re.compile(
    r"(?ix)(?:"
    r"(?:select|insert|update|delete)\b.{0,160}(?:\+\s*(?:request|req|params|query|body)|"
    r"\$\{\s*(?:request|req|params|query|body))|"
    r"(?:execute|executemany|raw|query)\s*\(.{0,160}(?:request|req\.|params|query|body)"
    r")"
)
# Lines that define a regex/pattern (rather than executing one) — skip risky-pattern
# matching on them so a scanner, linter, or rules file that *names* these patterns
# doesn't get flagged for the very patterns it's documenting.
PATTERN_DEF = re.compile(r"re\.compile\(|regexp?\.(?:compile|MustCompile)\(|new RegExp\(")


def _git(root: Path, *args: str) -> str:
    try:
        return subprocess.run(["git", "-C", str(root), *args],
                              capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return ""


def _redact(text: str) -> str:
    text = text.strip()
    if len(text) > 90:
        text = text[:87] + "..."
    return re.sub(r"([A-Za-z0-9_\-]{6})[A-Za-z0-9_\-]{6,}", r"\1********", text)


def _iter_files(root: Path):
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if any(part.endswith((".egg-info", ".dist-info"))
               for part in p.relative_to(root).parts):
            continue
        if p.suffix.lower() in SKIP_EXT:
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


def _is_allowed_secret(match: re.Match) -> bool:
    """Apply placeholder exceptions only to the matched credential, not its line."""
    return bool(SECRET_ALLOW.search(match.group(0)))


def scan(root: Path, agent_only: bool = False) -> ScanResult:
    root = root.resolve()
    findings: list = []
    notes: list = []
    stack = detect_stack(root)
    files_scanned = 0

    # Agent-layer checks always run (the differentiator).
    findings.extend(scan_agent_layer(root))

    if not agent_only:
        if (root / ".git").exists():
            for f in _git(root, "ls-files").splitlines():
                base = f.rsplit("/", 1)[-1]
                if re.match(r"\.env(\..+)?$", base) and not base.endswith(".example"):
                    findings.append(Finding("HIGH", "secrets",
                        "A .env file is tracked by git and likely contains secrets.", path=f))
        else:
            notes.append("Not a git repository — history-based checks skipped.")

        for path in _iter_files(root):
            rel = str(path.relative_to(root))
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            files_scanned += 1
            is_doc = rel.endswith(".md") or "/docs/" in f"/{rel}"
            for lineno, line in enumerate(text.splitlines(), 1):
                for name, pat in SECRET_PATTERNS:
                    match = pat.search(line)
                    if match and not _is_allowed_secret(match):
                        findings.append(Finding("HIGH", "secrets",
                            f"Possible hardcoded secret ({name}).",
                            path=rel, line=lineno, snippet=_redact(line)))
                        break
                public_match = PUBLIC_PREFIX.search(line)
                if (not is_doc and public_match
                        and not PUBLIC_OK.search(public_match.group(0))):
                    findings.append(Finding("HIGH", "secrets",
                        "Server-only secret exposed via a public env prefix "
                        "(ships to the browser).",
                        path=rel, line=lineno, snippet=_redact(line)))
                if (not is_doc and not path.name.endswith(".example")
                        and not PATTERN_DEF.search(line)):
                    if SQL_INJECTION.search(line):
                        findings.append(Finding("HIGH", "code",
                            "Possible SQL injection: request-controlled data appears to be "
                            "used in a SQL statement. Use a parameterized query.",
                            path=rel, line=lineno, snippet=line.strip()[:90]))
                    for name, pat in RISKY_PATTERNS:
                        if pat.search(line):
                            findings.append(Finding("MEDIUM", "code",
                                f"Risky pattern worth review: {name}.",
                                path=rel, line=lineno, snippet=line.strip()[:90]))
                            break
        _audit_deps(root, stack, findings, notes)

    findings.sort(key=lambda f: f.sort_key())
    return ScanResult(findings, notes, stack, files_scanned)


def _audit_deps(root, stack, findings, notes):
    if stack.has("node") and (root / "package.json").is_file() and shutil.which("npm"):
        try:
            proc = subprocess.run(["npm", "audit", "--audit-level=high", "--json"],
                                  cwd=root, capture_output=True, text=True, timeout=120)
            meta = json.loads(proc.stdout or "{}").get("metadata", {}).get("vulnerabilities", {})
            high = meta.get("high", 0) + meta.get("critical", 0)
            if high:
                findings.append(Finding("HIGH", "dependencies",
                    f"npm audit reports {high} high/critical vulnerabilities."))
            elif meta:
                notes.append("npm audit: no high/critical vulnerabilities.")
            else:
                notes.append("npm audit could not run (no lockfile or offline).")
        except Exception:
            notes.append("npm audit could not run (no lockfile or offline).")
    if stack.has("python"):
        if shutil.which("pip-audit"):
            try:
                requirements = root / "requirements.txt"
                if not requirements.is_file():
                    notes.append("pip-audit skipped: no requirements.txt dependency input.")
                else:
                    proc = subprocess.run(
                        ["pip-audit", "-r", str(requirements), "-f", "json"], cwd=root,
                        capture_output=True, text=True, timeout=120)
                    if proc.returncode == 1 and proc.stdout.strip() not in ("", "[]"):
                        findings.append(Finding("HIGH", "dependencies",
                            "pip-audit reports known vulnerabilities."))
                    elif proc.returncode == 0:
                        notes.append("pip-audit: no known vulnerabilities.")
                    else:
                        notes.append("pip-audit could not audit requirements.txt.")
            except Exception:
                notes.append("pip-audit could not run.")
        else:
            notes.append("Python project detected but pip-audit not installed.")
