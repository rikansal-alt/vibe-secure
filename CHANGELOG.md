# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `vibe-secure investigate`: a read-only security investigation agent with a
  repository-specific threat model, required coverage plan, bounded tools,
  source-line evidence validation, and deterministic reporting.
- Stack-specific coverage tasks for web authorization/input flow, Supabase,
  Firebase, and Python server sinks.
- JSON investigation output containing task state, validated findings, tool-call
  counts, and the model's final summary.

### Fixed
- Agent-layer scan no longer flags `requireApproval` (the *secure* setting) as an
  auto-run risk.
- JSONC editor settings preserve comment-like text inside quoted strings and
  auto-run findings retain source line/snippet evidence.
- Productive investigation tool calls reset the premature-final retry budget.
- Skipping `pip-audit` for a missing `requirements.txt` no longer exits the
  entire dependency-audit orchestrator early.
- Risky-pattern scanning skips lines that merely *define* a regex, so a scanner,
  linter, or rules file that names a pattern isn't flagged for it.

### Changed
- Restructured into a `src/` layout with `tests/`, `docs/`, and CI.
- Softened unverifiable specifics in the docs to defensible claims.
- Clarified that offline scanning is dependency-free while AI investigation is
  an optional, metered API layer that transmits selected redacted source excerpts.
- Documented investigator prompt-injection containment and residual risk, and
  replaced the premature PyPI install command with the GitHub installation path.

## [0.2.0]

- Agent-layer checks: MCP server trust, auto-run/approval settings, agent rules
  hygiene, and a DuneSlide patch advisory for Cursor projects.
- App-layer checks: hardcoded secrets, public-prefix leaks, risky patterns,
  git-tracked `.env`, and `npm audit` / `pip-audit` integration.
