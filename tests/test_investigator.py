"""Offline tests for the read-only investigation agent."""
import json

import pytest

from vibe_secure.investigation import EvidenceItem, build_investigation
from vibe_secure.investigator import InvestigationError, RepositoryTools, investigate


def test_agent_uses_read_only_repository_tool(tmp_path):
    (tmp_path / "app.py").write_text("password = request.args['password']\n", encoding="utf-8")
    requests = []

    def transport(payload):
        requests.append(payload)
        if len(requests) == 1:
            return {"output": [{
                "type": "function_call", "name": "read_file", "call_id": "call_1",
                "arguments": json.dumps({"path": "app.py", "start_line": 1, "end_line": 20}),
            }]}
        assert any(item.get("type") == "function_call_output" and "password" in item["output"]
                   for item in payload["input"])
        if len(requests) == 2:
            return {"output": [{
                "type": "function_call", "name": "complete_task", "call_id": f"done_{task}",
                "arguments": json.dumps({"task_id": task, "summary": "Reviewed relevant files."}),
            } for task in ("VS-BASELINE", "VS-SECRETS", "VS-SUPPLY", "VS-PYTHON")]}
        return {"output": [{
            "type": "message",
            "content": [{"type": "output_text", "text": "## Summary\nReview app.py:1"}],
        }]}

    result = investigate(tmp_path, model="mock-model", transport=transport)
    assert result.tool_calls == 5
    assert result.model == "mock-model"
    assert "## Coverage" in result.report
    assert "app.py:1" in result.model_summary
    assert result.state.complete


def test_repository_tool_blocks_path_escape(tmp_path):
    tools = RepositoryTools(tmp_path)
    with pytest.raises(InvestigationError, match="escapes repository"):
        tools.call("read_file", {"path": "../secret", "start_line": 1, "end_line": 2})


def test_repository_tool_caps_read_range(tmp_path):
    (tmp_path / "long.txt").write_text("\n".join(str(i) for i in range(1000)), encoding="utf-8")
    output = RepositoryTools(tmp_path).call(
        "read_file", {"path": "long.txt", "start_line": 1, "end_line": 1000})
    assert len(output.splitlines()) == 400


def test_repository_tools_do_not_expose_credentials(tmp_path):
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-secret-value\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        'token = "abcdefghijklmnopqrstuvwxyz"\n', encoding="utf-8")
    tools = RepositoryTools(tmp_path)
    with pytest.raises(InvestigationError, match="not available"):
        tools.call("read_file", {"path": ".env", "start_line": 1, "end_line": 2})
    output = tools.call("read_file", {"path": "app.py", "start_line": 1, "end_line": 2})
    assert "abcdefghijklmnopqrstuvwxyz" not in output
    assert "REDACTED" in output


def test_agent_rejects_empty_final_response(tmp_path):
    with pytest.raises(InvestigationError, match="did not complete required coverage"):
        investigate(tmp_path, transport=lambda payload: {"output": []})


def test_productive_tool_calls_reset_premature_final_limit(tmp_path):
    (tmp_path / "app.py").write_text("safe = True\n", encoding="utf-8")
    turn = 0

    def transport(payload):
        nonlocal turn
        turn += 1
        if turn in {1, 3, 5}:
            return {"output": []}
        if turn in {2, 4}:
            return {"output": [{
                "type": "function_call", "name": "read_file", "call_id": f"read_{turn}",
                "arguments": json.dumps({"path": "app.py", "start_line": 1, "end_line": 1}),
            }]}
        if turn == 6:
            return {"output": [{
                "type": "function_call", "name": "complete_task", "call_id": f"done_{task}",
                "arguments": json.dumps({"task_id": task, "summary": "Reviewed."}),
            } for task in ("VS-BASELINE", "VS-SECRETS", "VS-SUPPLY", "VS-PYTHON")]}
        return {"output": [{
            "type": "message",
            "content": [{"type": "output_text", "text": "Complete."}],
        }]}

    result = investigate(tmp_path, model="mock-model", transport=transport)
    assert result.state.complete
    assert turn == 7


def test_recorded_evidence_must_match_source_line(tmp_path):
    (tmp_path / "app.py").write_text("safe = True\n", encoding="utf-8")
    tools = RepositoryTools(tmp_path)
    with pytest.raises(InvestigationError, match="does not match"):
        tools.validate_evidence("app.py", 1, "eval(user_input)")


def test_nextjs_authorization_operations_are_inventoried(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"next": "15.0.0"}}), encoding="utf-8")
    route = tmp_path / "app/api/projects/[id]/route.ts"
    route.parent.mkdir(parents=True)
    route.write_text(
        "export async function GET() {}\n"
        "export async function DELETE() {}\n", encoding="utf-8")

    state = build_investigation(tmp_path)
    assert [(op.method, op.route) for op in state.operations] == [
        ("GET", "/api/projects/:id"), ("DELETE", "/api/projects/:id")]
    assert not state.complete
    assert state.authorization_coverage["total"] == 2


def test_authorization_classification_requires_evidence(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"next": "15.0.0"}}), encoding="utf-8")
    route = tmp_path / "app/api/projects/[id]/route.ts"
    route.parent.mkdir(parents=True)
    route.write_text("export async function DELETE() {}\n", encoding="utf-8")
    state = build_investigation(tmp_path)

    with pytest.raises(ValueError, match="requires source evidence"):
        state.classify_operation(
            "AUTH-OP-001", "vulnerable", "verified", "verified", "missing",
            "No ownership check.", [])
    state.classify_operation(
        "AUTH-OP-001", "vulnerable", "verified", "verified", "missing",
        "No ownership check.",
        [EvidenceItem(str(route.relative_to(tmp_path)), 1,
                      "export async function DELETE() {}")])
    assert state.authorization_coverage["vulnerable"] == 1
    assert state.authorization_coverage["percent_verified_protected"] == 0


def test_protected_operation_requires_all_authorization_dimensions(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"next": "15.0.0"}}), encoding="utf-8")
    route = tmp_path / "app/api/account/route.ts"
    route.parent.mkdir(parents=True)
    route.write_text("export async function GET() {}\n", encoding="utf-8")
    state = build_investigation(tmp_path)
    evidence = [EvidenceItem(str(route.relative_to(tmp_path)), 1,
                             "export async function GET() {}")]
    with pytest.raises(ValueError, match="requires verified"):
        state.classify_operation(
            "AUTH-OP-001", "protected", "verified", "unknown", "unknown",
            "Session exists but authorization is unclear.", evidence)
