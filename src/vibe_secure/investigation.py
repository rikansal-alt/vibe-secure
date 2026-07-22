"""Deterministic investigation state for the model-powered security agent."""
from __future__ import annotations

import json
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

    @property
    def complete(self) -> bool:
        return all(task.status == "completed" for task in self.tasks)

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

    def as_dict(self) -> dict:
        return {
            "threat_model": asdict(self.threat_model),
            "tasks": [asdict(task) for task in self.tasks],
            "findings": [asdict(finding) for finding in self.findings],
            "complete": self.complete,
        }

    def as_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2)


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
    return InvestigationState(threat, tasks)
