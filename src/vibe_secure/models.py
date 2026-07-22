"""Shared data models."""
from __future__ import annotations

from dataclasses import dataclass

SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class Finding:
    severity: str
    category: str          # secrets | code | dependencies | agent
    message: str
    path: str = ""
    line: int = 0
    snippet: str = ""

    def sort_key(self):
        return (-SEVERITY_RANK[self.severity], self.category, self.path, self.line)


@dataclass
class ScanResult:
    findings: list
    notes: list
    stack: object
    files_scanned: int

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def agent_count(self) -> int:
        return sum(1 for f in self.findings if f.category == "agent")

    def by_severity(self) -> dict:
        out = {"HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for f in self.findings:
            out[f.severity].append(f)
        return out
