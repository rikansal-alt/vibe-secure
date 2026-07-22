"""Deterministic investigation state for the model-powered security agent."""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .detect import detect_stack


@dataclass
class InvestigationTask:
    id: str
    title: str
    objective: str
    status: str = "pending"
    summary: str = ""


@dataclass
class AgentFinding:
    task_id: str
    severity: str
    confidence: str
    title: str
    path: str
    line: int
    evidence: str
    remediation: str


@dataclass
class EvidenceItem:
    path: str
    line: int
    text: str


@dataclass
class ProtectedOperation:
    id: str
    method: str
    route: str
    path: str
    line: int
    sensitivity: str
    classification: str = "unknown"
    authentication: str = "unknown"
    authorization: str = "unknown"
    ownership: str = "unknown"
    rationale: str = ""
    evidence: list = field(default_factory=list)


@dataclass
class ThreatModel:
    stacks: list
    assets: list
    trust_boundaries: list
    attack_surfaces: list


@dataclass
class InvestigationState:
    threat_model: ThreatModel
    tasks: list
    findings: list = field(default_factory=list)
    operations: list = field(default_factory=list)

    @property
    def complete(self) -> bool:
        tasks_complete = all(task.status == "completed" for task in self.tasks)
        operations_complete = all(op.classification != "unknown" for op in self.operations)
        return tasks_complete and operations_complete

    @property
    def authorization_coverage(self) -> dict:
        counts = {name: 0 for name in ("protected", "vulnerable", "not_verified", "not_applicable")}
        for operation in self.operations:
            if operation.classification in counts:
                counts[operation.classification] += 1
        applicable = len(self.operations) - counts["not_applicable"]
        counts["total"] = len(self.operations)
        counts["percent_verified_protected"] = (
            round(counts["protected"] * 100 / applicable) if applicable else 100)
        return counts

    def task(self, task_id: str) -> InvestigationTask:
        for task in self.tasks:
            if task.id == task_id:
                return task
        raise ValueError(f"unknown task: {task_id}")

    def complete_task(self, task_id: str, summary: str) -> None:
        task = self.task(task_id)
        if not summary.strip():
            raise ValueError("coverage summary is required")
        task.status = "completed"
        task.summary = summary.strip()[:1000]

    def operation(self, operation_id: str) -> ProtectedOperation:
        for operation in self.operations:
            if operation.id == operation_id:
                return operation
        raise ValueError(f"unknown operation: {operation_id}")

    def classify_operation(self, operation_id: str, classification: str, authentication: str,
                           authorization: str, ownership: str, rationale: str, evidence: list) -> None:
        allowed = {"protected", "vulnerable", "not_verified", "not_applicable"}
        dimensions = {"verified", "missing", "unknown", "not_applicable"}
        if classification not in allowed:
            raise ValueError(f"invalid authorization classification: {classification}")
        if any(value not in dimensions for value in (authentication, authorization, ownership)):
            raise ValueError("invalid authorization dimension")
        if not rationale.strip():
            raise ValueError("authorization rationale is required")
        if classification in {"protected", "vulnerable"} and not evidence:
            raise ValueError(f"{classification} classification requires source evidence")
        if classification == "protected" and (
                authentication != "verified" or authorization != "verified"
                or ownership not in {"verified", "not_applicable"}):
            raise ValueError("protected requires verified authentication and authorization")
        if classification == "vulnerable" and "missing" not in {
                authentication, authorization, ownership}:
            raise ValueError("vulnerable requires at least one missing authorization dimension")
        operation = self.operation(operation_id)
        operation.classification = classification
        operation.authentication = authentication
        operation.authorization = authorization
        operation.ownership = ownership
        operation.rationale = rationale.strip()[:1000]
        operation.evidence = evidence

    def as_dict(self) -> dict:
        return {
            "threat_model": asdict(self.threat_model),
            "tasks": [asdict(task) for task in self.tasks],
            "findings": [asdict(finding) for finding in self.findings],
            "authorization_operations": [asdict(operation) for operation in self.operations],
            "authorization_coverage": self.authorization_coverage,
            "complete": self.complete,
        }

    def as_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2)


def _route_name(rel: str) -> str:
    route = "/" + rel.replace("\\", "/").lstrip("/")
    if "/app/api/" in route:
        route = "/api/" + route.split("/app/api/", 1)[1].rsplit("/route.", 1)[0]
    elif "/pages/api/" in route:
        route = "/api/" + route.split("/pages/api/", 1)[1].rsplit(".", 1)[0]
    return re.sub(r"\[\.\.\.(.+?)\]|\[(.+?)\]",
                  lambda m: f":{m.group(1) or m.group(2)}", route)


def inventory_authorization_operations(root: Path) -> list:
    """Inventory Next.js entry points and Supabase mutations deterministically."""
    candidates = []
    root = root.resolve()
    extensions = {".js", ".jsx", ".ts", ".tsx"}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in extensions:
            continue
        try:
            path.resolve().relative_to(root)
        except ValueError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        if any(part in {"node_modules", ".next", "dist", "build"} for part in Path(rel).parts):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        is_app_route = re.search(r"(^|/)app/api/(?:.*/)?route\.(?:js|jsx|ts|tsx)$", rel)
        is_pages_route = re.search(r"(^|/)pages/api/.+\.(?:js|jsx|ts|tsx)$", rel)
        if is_app_route:
            methods = []
            for lineno, line in enumerate(lines, 1):
                match = re.search(
                    r"export\s+(?:(?:async\s+)?function|const)\s+"
                    r"(GET|POST|PUT|PATCH|DELETE)\b", line)
                if match:
                    methods.append((match.group(1), lineno))
            for method, lineno in methods or [("HANDLER", 1)]:
                candidates.append((method, _route_name(rel), rel, lineno))
        elif is_pages_route:
            handler_line = next((n for n, line in enumerate(lines, 1)
                                 if re.search(r"export\s+default", line)), 1)
            candidates.append(("HANDLER", _route_name(rel), rel, handler_line))

        if re.search(r"(^|\n)\s*['\"]use server['\"]", text):
            for lineno, line in enumerate(lines, 1):
                match = re.search(r"export\s+(?:async\s+function|const)\s+([A-Za-z_$][\w$]*)", line)
                if match:
                    candidates.append(("SERVER_ACTION", match.group(1), rel, lineno))

        if "supabase" in text.lower() and not (is_app_route or is_pages_route):
            for lineno, line in enumerate(lines, 1):
                if re.search(r"\.(?:insert|update|upsert|delete)\s*\(", line):
                    candidates.append(("SUPABASE_MUTATION", rel, rel, lineno))

    operations = []
    for index, (method, route, path, line) in enumerate(candidates, 1):
        sensitivity = "high" if method not in {"GET", "HANDLER"} else "medium"
        operations.append(ProtectedOperation(
            f"AUTH-OP-{index:03d}", method, route, path, line, sensitivity))
    return operations


def build_investigation(root: Path) -> InvestigationState:
    """Build a repository-specific threat model and required coverage plan."""
    stack = detect_stack(root)
    stacks = sorted(stack.stacks)
    assets = ["source code", "application secrets", "dependency supply chain"]
    boundaries = ["untrusted repository content → security agent"]
    surfaces = ["hardcoded credentials", "known-vulnerable dependencies", "agent configuration"]
    tasks = [
        InvestigationTask(
            "VS-BASELINE", "Validate deterministic candidates",
            "Verify high-risk scanner candidates and reject obvious false positives."),
        InvestigationTask(
            "VS-SECRETS", "Review secret handling",
            "Check credential sources, public environment prefixes, and accidental client exposure."),
        InvestigationTask(
            "VS-SUPPLY", "Review dependency and execution surface",
            "Inspect manifests, install scripts, shell execution, and unpinned executable tooling."),
    ]

    if {"node", "nextjs", "react", "vite"} & stack.stacks:
        assets.extend(["user sessions", "server-side API operations"])
        boundaries.extend(["browser → server routes", "client bundle → server-only configuration"])
        surfaces.extend(["unprotected routes", "client-side secret exposure", "XSS", "SSRF"])
        tasks.extend([
            InvestigationTask(
                "VS-WEB-AUTH", "Map authentication and authorization",
                "Enumerate sensitive routes/actions and verify identity plus resource-level authorization."),
            InvestigationTask(
                "VS-WEB-INPUT", "Trace untrusted web input",
                "Review request data reaching SQL, HTML, commands, file paths, redirects, and outbound URLs."),
        ])
    if "supabase" in stack.stacks:
        assets.append("Supabase database rows and storage objects")
        boundaries.append("public Supabase client → database policies")
        surfaces.extend(["missing RLS", "service-role key exposure", "overbroad policies"])
        tasks.append(InvestigationTask(
            "VS-SUPABASE", "Verify Supabase isolation",
            "Map tables to RLS policies and check service-role usage and storage access."))
    if "firebase" in stack.stacks:
        assets.append("Firebase data and storage objects")
        boundaries.append("public Firebase client → security rules")
        surfaces.extend(["open Firebase rules", "missing ownership checks"])
        tasks.append(InvestigationTask(
            "VS-FIREBASE", "Verify Firebase authorization",
            "Review Firestore, Realtime Database, and Storage rules for authentication and ownership."))
    if "python" in stack.stacks:
        assets.append("Python server processes and data stores")
        boundaries.append("HTTP/request input → Python application")
        surfaces.extend(["template injection", "SQL injection", "unsafe subprocess use", "debug mode"])
        tasks.append(InvestigationTask(
            "VS-PYTHON", "Review Python server sinks",
            "Trace request-controlled values into SQL, templates, subprocesses, files, and outbound requests."))

    threat = ThreatModel(stacks or ["unknown"], list(dict.fromkeys(assets)),
                         list(dict.fromkeys(boundaries)), list(dict.fromkeys(surfaces)))
    operations = inventory_authorization_operations(root)
    return InvestigationState(threat, tasks, operations=operations)
