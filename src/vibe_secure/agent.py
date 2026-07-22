"""
Agent-layer security scanner: the DuneSlide-class checks.

Most vibe-coding scanners look at the code the AI wrote. This module looks at
the *agent's own configuration* — MCP server trust, auto-run/approval settings,
and whether the project teaches the agent any security guardrails at all.

Motivated by DuneSlide (CVE-2026-50548 / CVE-2026-50549), where a prompt
injection carried in content the agent reads (a poisoned MCP response or web
result) escaped Cursor's sandbox and ran code with no user click. That class of
risk lives in the agent's setup, not in the app source, so it needs its own scan.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Finding

# Well-known agent config locations (relative to repo root).
MCP_CONFIG_PATHS = [
    ".cursor/mcp.json", ".mcp.json", "mcp.json",
    ".vscode/mcp.json", "claude_desktop_config.json",
    ".claude/mcp.json", ".windsurf/mcp.json",
]
EDITOR_SETTINGS_PATHS = [
    ".cursor/settings.json", ".vscode/settings.json",
    ".cursor/environment.json", ".windsurf/settings.json",
]
RULES_FILES = [
    ".cursorrules", "AGENTS.md", ".cursor/rules",
    ".windsurfrules", ".github/copilot-instructions.md", "CLAUDE.md",
]

# Config keys/values that indicate the agent may execute actions without a human
# in the loop. We flag these for REVIEW rather than asserting exact semantics —
# the point is to surface auto-execution surface area, not to guess intent.
# NOTE: we deliberately do NOT match "require approval" here — requiring approval
# is the *safe* setting, and flagging it produced a false positive.
AUTORUN_HINTS = re.compile(
    r"(?i)\"?(auto[_-]?run|auto[_-]?approve|auto[_-]?execute|yolo|"
    r"skip[_-]?approval|autonomous|allow[_-]?all|"
    r"dangerously[_-]?allow|no[_-]?confirm)\"?"
)


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _strip_jsonc(text: str) -> str:
    """Remove JSONC comments/trailing commas without touching quoted strings."""
    out = []
    i = 0
    in_string = False
    escaped = False
    while i < len(text):
        char = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_string:
            out.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            i += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            i += 1
            continue
        if char == "/" and nxt == "/":
            i += 2
            while i < len(text) and text[i] not in "\r\n":
                i += 1
            continue
        if char == "/" and nxt == "*":
            i += 2
            while i + 1 < len(text) and text[i:i + 2] != "*/":
                if text[i] in "\r\n":
                    out.append(text[i])
                i += 1
            i += 2
            continue
        if char == ",":
            lookahead = i + 1
            while lookahead < len(text) and text[lookahead].isspace():
                lookahead += 1
            if lookahead < len(text) and text[lookahead] in "}]":
                i += 1
                continue
        out.append(char)
        i += 1
    return "".join(out)


def _read_jsonc(path: Path):
    """Read editor JSON-with-comments without adding a runtime dependency."""
    try:
        return json.loads(_strip_jsonc(path.read_text(encoding="utf-8")))
    except Exception:
        return None


def _enabled_autorun_values(value, key: str = "") -> list:
    """Return enabled approval-skipping settings, while ignoring false/empty values."""
    hits = []
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            hits.extend(_enabled_autorun_values(child_value, str(child_key)))
    elif isinstance(value, list):
        if key and AUTORUN_HINTS.search(key) and value:
            hits.append(key)
        else:
            for child in value:
                hits.extend(_enabled_autorun_values(child, key))
    elif key and AUTORUN_HINTS.search(key):
        if value is True or (isinstance(value, str)
                             and value.strip().lower() in {"true", "yes", "all", "always", "on"}):
            hits.append(key)
    elif isinstance(value, str) and AUTORUN_HINTS.search(value):
        hits.append(value)
    return hits


def scan_agent_layer(root: Path) -> list:
    """Return agent-layer findings for a repo."""
    findings: list = []
    _check_mcp(root, findings)
    _check_editor_settings(root, findings)
    _check_rules_hygiene(root, findings)
    _check_cursor_advisory(root, findings)
    return findings


def _check_mcp(root: Path, findings: list) -> None:
    for rel in MCP_CONFIG_PATHS:
        path = root / rel
        if not path.is_file():
            continue
        data = _read_json(path)
        if data is None:
            findings.append(Finding(
                "MEDIUM", "agent",
                "Could not parse MCP configuration; its security settings were not evaluated.",
                path=rel,
            ))
            continue
        if not data:
            continue
        servers = data.get("mcpServers") or data.get("servers") or {}
        if not isinstance(servers, dict):
            continue
        for name, cfg in servers.items():
            cfg = cfg if isinstance(cfg, dict) else {}
            # 1. Local command execution servers (broad trust).
            if cfg.get("command"):
                findings.append(Finding(
                    "MEDIUM", "agent",
                    f"MCP server '{name}' runs a local command "
                    f"({cfg.get('command')}). Its output is trusted by the "
                    "agent; treat it as an untrusted input path (DuneSlide class).",
                    path=rel,
                ))
            # 2. Remote URL servers — the poisoned-response vector.
            url = cfg.get("url") or cfg.get("uri") or ""
            if isinstance(url, str) and url.startswith(("http://", "https://")):
                sev = "HIGH" if url.startswith("http://") else "MEDIUM"
                findings.append(Finding(
                    sev, "agent",
                    f"MCP server '{name}' pulls from a remote URL "
                    f"({'insecure http' if sev=='HIGH' else 'remote'}). A poisoned "
                    "response can inject instructions the agent will act on.",
                    path=rel,
                ))
            # 3. Auto-approve on a server.
            blob = json.dumps(cfg)
            if _enabled_autorun_values(cfg):
                findings.append(Finding(
                    "HIGH", "agent",
                    f"MCP server '{name}' appears to auto-approve or auto-run "
                    "actions. Combined with a poisoned response, this is the "
                    "zero-click path. Require human approval.",
                    path=rel,
                ))
            # 4. Secrets sitting in the MCP config.
            if re.search(r"(?i)(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|"
                         r"AKIA[0-9A-Z]{16}|\"(api[_-]?key|token|secret)\"\s*:\s*\"[^\"]{12,})", blob):
                findings.append(Finding(
                    "HIGH", "secrets",
                    f"MCP config for '{name}' appears to contain a hardcoded "
                    "credential. Move it to an environment variable.",
                    path=rel,
                ))


def _check_editor_settings(root: Path, findings: list) -> None:
    for rel in EDITOR_SETTINGS_PATHS:
        path = root / rel
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        data = _read_jsonc(path)
        if data is None:
            findings.append(Finding(
                "MEDIUM", "agent",
                "Could not parse editor settings; agent execution permissions were not evaluated.",
                path=rel,
            ))
            continue
        for setting in sorted(set(_enabled_autorun_values(data))):
            setting_line = next(
                ((lineno, line.strip()[:90])
                 for lineno, line in enumerate(text.splitlines(), 1) if setting in line),
                (0, ""),
            )
            findings.append(Finding(
                "MEDIUM", "agent",
                f"Agent auto-run / approval-skipping setting '{setting}' is enabled. "
                "Review whether terminal commands can run without human confirmation.",
                path=rel, line=setting_line[0], snippet=setting_line[1],
            ))


def _check_rules_hygiene(root: Path, findings: list) -> None:
    """Positive check: does the project teach the agent any security rules?"""
    present = [r for r in RULES_FILES if (root / r).exists()]
    if not present:
        findings.append(Finding(
            "LOW", "agent",
            "No agent rules file found (.cursorrules, AGENTS.md, CLAUDE.md, "
            "etc.). A rules file that forbids hardcoded secrets, bans eval, and "
            "requires parameterized queries is your cheapest guardrail.",
        ))
        return
    # A rules file exists — check it actually says something about security.
    security_terms = re.compile(
        r"(?i)(secret|api[_-]?key|parameteri|sql injection|eval\(|"
        r"sanitiz|validate|env(ironment)? variable|never commit)")
    for r in present:
        p = root / r
        if p.is_file():
            txt = p.read_text(encoding="utf-8", errors="ignore")
            if not security_terms.search(txt):
                findings.append(Finding(
                    "LOW", "agent",
                    f"Agent rules file '{r}' exists but contains no security "
                    "directives. Add rules the agent must follow (no hardcoded "
                    "secrets, parameterized queries, validate input).",
                    path=r,
                ))


def _check_cursor_advisory(root: Path, findings: list) -> None:
    """Advisory if the repo shows signs of Cursor use (DuneSlide patch reminder)."""
    if (root / ".cursor").exists() or (root / ".cursorrules").is_file():
        findings.append(Finding(
            "INFO", "agent",
            "Cursor config detected. DuneSlide (CVE-2026-50548/50549, CVSS 9.8) "
            "affected every Cursor before 3.0. Confirm you are on 3.0+, and treat "
            "all MCP and web content the agent reads as untrusted input.",
        ))
