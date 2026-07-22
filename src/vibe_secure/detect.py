"""Detect stack and agent tooling to tailor scanning."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

_CODEQL = {"node": "javascript-typescript", "python": "python",
           "go": "go", "ruby": "ruby", "java": "java-kotlin"}


@dataclass
class StackInfo:
    stacks: set = field(default_factory=set)
    agents: set = field(default_factory=set)

    @property
    def codeql_languages(self) -> list:
        langs = {_CODEQL[s] for s in self.stacks if s in _CODEQL}
        return sorted(langs) or ["javascript-typescript"]

    def has(self, name: str) -> bool:
        return name in self.stacks

    def label(self) -> str:
        s = ", ".join(sorted(self.stacks)) or "unknown"
        if self.agents:
            s += "  |  agents: " + ", ".join(sorted(self.agents))
        return s


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def detect_stack(root: Path) -> StackInfo:
    info = StackInfo()
    pkg = root / "package.json"
    if pkg.is_file():
        info.stacks.add("node")
        data = _read_json(pkg)
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        names = " ".join(deps).lower()
        for k, tag in (("next", "nextjs"), ("react", "react"), ("vite", "vite")):
            if k in names:
                info.stacks.add(tag)
        if "@supabase/supabase-js" in deps:
            info.stacks.add("supabase")
        if "firebase" in deps or "firebase-admin" in deps:
            info.stacks.add("firebase")
    if (root / "requirements.txt").is_file() or (root / "pyproject.toml").is_file():
        info.stacks.add("python")
    if (root / "go.mod").is_file():
        info.stacks.add("go")
    if (root / "Gemfile").is_file():
        info.stacks.add("ruby")
    if any((root / f).is_file() for f in ("firebase.json", ".firebaserc")):
        info.stacks.add("firebase")
    if (root / "supabase").exists():
        info.stacks.add("supabase")

    # Agent tooling
    if (root / ".cursor").exists() or (root / ".cursorrules").is_file():
        info.agents.add("cursor")
    if (root / ".windsurf").exists() or (root / ".windsurfrules").is_file():
        info.agents.add("windsurf")
    if (root / "CLAUDE.md").is_file() or (root / ".claude").exists():
        info.agents.add("claude-code")
    if (root / ".github" / "copilot-instructions.md").is_file():
        info.agents.add("copilot")
    if (root / ".amazonq").exists():
        info.agents.add("amazon-q")
    return info
