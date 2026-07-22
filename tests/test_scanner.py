"""Tests for vibe-secure, including the agent-layer differentiator."""
import json
from pathlib import Path

from vibe_secure.report import render_html
from vibe_secure.scanner import scan


def _w(root: Path, rel: str, content: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


# Built at runtime so the literal never forms a scannable Stripe token in this
# file's git history (would otherwise trip GitHub push protection). The fixture
# written to the temp repo is a full key, so detection is still exercised.
_FAKE_STRIPE = "sk_live_" + "0123456789abcdefghij" * 2


# --- classic checks ---------------------------------------------------------
def test_stripe_secret(tmp_path):
    _w(tmp_path, "s.js", f'new Stripe("{_FAKE_STRIPE}")')
    assert scan(tmp_path).high_count >= 1


def test_publishable_key_ok(tmp_path):
    _w(tmp_path, ".env", "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_x\n")
    r = scan(tmp_path)
    assert not any("public env prefix" in f.message for f in r.findings)


# --- agent-layer checks -----------------------------------------------------
def test_mcp_remote_http_flagged(tmp_path):
    _w(tmp_path, ".cursor/mcp.json",
       json.dumps({"mcpServers": {"weather": {"url": "http://evil.example/mcp"}}}))
    r = scan(tmp_path)
    assert any(f.category == "agent" and "poisoned" in f.message.lower()
               for f in r.findings)
    assert any(f.severity == "HIGH" for f in r.findings)


def test_mcp_autoapprove_flagged(tmp_path):
    _w(tmp_path, ".mcp.json",
       json.dumps({"mcpServers": {"fs": {"command": "npx", "autoApprove": ["all"]}}}))
    r = scan(tmp_path)
    assert any(f.category == "agent" and "auto" in f.message.lower()
               for f in r.findings)


def test_mcp_secret_flagged(tmp_path):
    _w(tmp_path, ".cursor/mcp.json",
       json.dumps({"mcpServers": {"x": {"env": {"API_KEY": "sk-abcdef0123456789xyz"}}}}))
    r = scan(tmp_path)
    assert any(f.category == "secrets" and "MCP" in f.message for f in r.findings)


def test_autorun_setting_flagged(tmp_path):
    _w(tmp_path, ".vscode/settings.json", '{ "cursor.agent.autoRun": true }')
    r = scan(tmp_path)
    assert any(f.category == "agent" and "auto-run" in f.message.lower()
               for f in r.findings)


def test_require_approval_not_flagged(tmp_path):
    """The secure setting (requiring approval) must NOT be reported as a risk."""
    _w(tmp_path, ".vscode/settings.json", '{ "cursor.agent.requireApproval": true }')
    r = scan(tmp_path)
    assert not any(f.category == "agent" and "auto-run" in f.message.lower()
                   for f in r.findings)


def test_disabled_autorun_not_flagged(tmp_path):
    _w(tmp_path, ".vscode/settings.json", '{ "cursor.agent.autoRun": false }')
    r = scan(tmp_path)
    assert not any(f.category == "agent" and "auto-run" in f.message.lower()
                   for f in r.findings)


def test_empty_autoapprove_not_flagged(tmp_path):
    _w(tmp_path, ".mcp.json",
       json.dumps({"mcpServers": {"fs": {"command": "npx", "autoApprove": []}}}))
    r = scan(tmp_path)
    assert not any(f.severity == "HIGH" and "auto-approve" in f.message.lower()
                   for f in r.findings)


def test_malformed_mcp_config_is_visible(tmp_path):
    _w(tmp_path, ".mcp.json", "{ definitely not json")
    r = scan(tmp_path)
    assert any(f.category == "agent" and "could not parse" in f.message.lower()
               for f in r.findings)


def test_jsonc_editor_settings_are_parsed(tmp_path):
    _w(tmp_path, ".vscode/settings.json",
       '{\n // project setting\n "cursor.agent.autoRun": true,\n}')
    r = scan(tmp_path)
    assert any(f.category == "agent" and "auto-run" in f.message.lower()
               for f in r.findings)


def test_jsonc_comment_markers_inside_strings_are_preserved(tmp_path):
    _w(tmp_path, ".vscode/settings.json",
       '{\n "note": "use a // b and /* c */",\n "cursor.agent.autoRun": true,\n}')
    r = scan(tmp_path)
    findings = [f for f in r.findings if f.category == "agent"
                and "auto-run" in f.message.lower()]
    assert len(findings) == 1
    assert findings[0].line == 3
    assert "autoRun" in findings[0].snippet
    assert not any("could not parse editor" in f.message.lower() for f in r.findings)


def test_missing_rules_file_noted(tmp_path):
    _w(tmp_path, "index.js", "console.log(1)")
    r = scan(tmp_path)
    assert any(f.category == "agent" and "rules file" in f.message.lower()
               for f in r.findings)


def test_cursor_advisory_present(tmp_path):
    _w(tmp_path, ".cursorrules", "never commit secrets. use parameterized queries.")
    r = scan(tmp_path)
    assert any("DuneSlide" in f.message for f in r.findings)
    # rules file has security terms, so no 'no security directives' finding
    assert not any("no security directives" in f.message for f in r.findings)


def test_agent_only_mode(tmp_path):
    _w(tmp_path, "s.js", f'new Stripe("{_FAKE_STRIPE}")')
    _w(tmp_path, ".cursor/mcp.json",
       json.dumps({"mcpServers": {"x": {"url": "http://evil/mcp"}}}))
    r = scan(tmp_path, agent_only=True)
    # agent findings present, app secret NOT scanned in agent-only mode
    assert any(f.category == "agent" for f in r.findings)
    assert not any(f.category == "secrets" and "Stripe" in f.message for f in r.findings)


def test_regex_definition_not_flagged_as_risky(tmp_path):
    """A line that *defines* a pattern (e.g. names eval/subprocess) isn't a usage."""
    _w(tmp_path, "patterns.py",
       'import re\nBAD = re.compile(r"eval\\\\(|subprocess\\\\.run")\n')
    r = scan(tmp_path)
    assert not any(f.category == "code" for f in r.findings)


def test_secret_allowlist_does_not_suppress_another_value_on_line(tmp_path):
    _w(tmp_path, "app.py",
       'token="abcdefghijklmnopqrstuvwxyz"; safe = process.env.OTHER\n')
    r = scan(tmp_path)
    assert any(f.category == "secrets" and f.severity == "HIGH" for f in r.findings)


def test_obvious_sql_concatenation_flagged(tmp_path):
    _w(tmp_path, "app.py",
       'q = "SELECT * FROM users WHERE id = " + request.args["id"]\n')
    r = scan(tmp_path)
    assert any(f.category == "code" and "SQL injection" in f.message for f in r.findings)


def test_generated_package_metadata_skipped(tmp_path):
    _w(tmp_path, "src/demo.egg-info/PKG-INFO", "dangerouslySetInnerHTML\n")
    r = scan(tmp_path)
    assert not any(f.category == "code" for f in r.findings)


# --- HTML report ------------------------------------------------------------
def test_html_report_is_self_contained_and_escapes(tmp_path):
    _w(tmp_path, "s.js", f'new Stripe("{_FAKE_STRIPE}")')
    _w(tmp_path, "x.jsx", 'foo.dangerouslySetInnerHTML={{__html:"<script>bad</script>"}}')
    doc = render_html(scan(tmp_path), root="demo")
    assert doc.startswith("<!doctype html>")
    assert "demo" in doc and "Fix before shipping" in doc
    # no external assets — fully self-contained
    assert "http://" not in doc and "https://" not in doc
    # snippet content is HTML-escaped, never a live tag
    assert "<script>bad" not in doc
    assert "&lt;script&gt;bad" in doc


def test_html_report_clean_repo(tmp_path):
    _w(tmp_path, "ok.py", "x = 1\n")
    _w(tmp_path, "CLAUDE.md",
       "never commit secrets. never use eval. use parameterized queries.")
    doc = render_html(scan(tmp_path), root="clean")
    assert "Clean — no findings." in doc
