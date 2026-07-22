# vibe-secure

**Scan your vibe-coded app *and* the AI agent that built it.**

Most security scanners for AI-built apps check the code the agent wrote:
hardcoded secrets, SQL injection, open database rules. Those matter, and
vibe-secure checks them too. But there's a second attack surface almost nobody
scans — **the agent's own configuration**.

In July 2026, Cato AI Labs disclosed **DuneSlide** (CVE-2026-50548 /
CVE-2026-50549, CVSS 9.8): a prompt injection hidden in content a Cursor agent
read on your behalf — a connected MCP server, a poisoned web result — escaped the
sandbox and ran code on the developer's machine. No click. And it isn't a one-off:
prompt injection is architectural, so similar sandbox-escape issues keep surfacing
across AI coding tools.

That risk doesn't live in your app source. It lives in your MCP config, your
auto-run settings, and whether your project teaches the agent any rules at all.
So vibe-secure scans that layer directly.

```
$ vibe-secure scan
HIGH  MCP server 'web-search' pulls from an insecure http URL. A poisoned
      response can inject instructions the agent will act on.
HIGH  MCP server 'filesystem' auto-approves actions. Combined with a poisoned
      response, this is the zero-click path. Require human approval.
INFO  Cursor config detected. DuneSlide (CVSS 9.8) affected every Cursor
      before 3.0. Confirm you are on 3.0+.

(All 3 findings here are agent-layer — the part other scanners miss.)
```

## Install

`vibe-secure` is not published to PyPI yet. Install the current repository build:

```bash
pipx install git+https://github.com/rikansal-alt/vibe-secure.git
# or, for development: git clone the repo and run pip install -e ".[dev]"
```

## Use

```bash
vibe-secure scan             # full: app holes + agent-layer config
vibe-secure agent            # agent-layer only (MCP, auto-run, rules)
vibe-secure scan --json      # machine-readable, for CI
vibe-secure scan --strict    # fail on any finding, not just high severity
vibe-secure scan --html report.html   # self-contained HTML report
vibe-secure investigate      # read-only AI investigation and verification
```

The deterministic `scan` and `agent` commands are free, offline, and implemented
with the Python standard library. They exit non-zero on high-severity findings,
so they drop into CI without a hosted model or API key.

### Example report

[`examples/sample-report.html`](examples/sample-report.html) is a real
`scan --html` report for a small demo app with a spread of findings — agent-layer
MCP/auto-run risks, a browser-exposed service-role key, a hardcoded secret
(redacted), and an XSS sink.
[**View it rendered**](https://htmlpreview.github.io/?https://github.com/rikansal-alt/vibe-secure/blob/main/examples/sample-report.html)
(GitHub shows `.html` as source). The report is theme-aware and self-contained —
no external assets, safe to attach to a CI run.

### AI investigation

The deterministic scan can optionally be followed by a read-only, tool-using
investigation. This layer requires an OpenAI API key, incurs API usage charges,
and sends selected, redacted source excerpts to the API:

```bash
export OPENAI_API_KEY="..."
vibe-secure investigate .
vibe-secure investigate . --json
vibe-secure investigate . --model gpt-5.6-sol
```

`gpt-5.6-sol` is the current documented model ID, not a project-local alias; see
the [official OpenAI model page](https://developers.openai.com/api/docs/models/gpt-5.6-sol).
Without a key, use `vibe-secure scan .` for the complete offline ruleset.

The model can list, search, and read bounded portions of repository files. It cannot
modify files or execute project commands. Repository content is treated as untrusted
data, tool calls are capped, and paths cannot escape the scanned repository.

#### Why this is an agent, not a scanner wrapper

`investigate` builds explicit investigation state before calling a model:

```text
repository inventory
        ↓
stack-specific threat model
        ↓
required coverage plan
        ↓
model investigates with read-only tools
        ↓
source-line evidence validator
        ↓
deterministic findings + coverage report
```

The model decides which files and hypotheses to investigate, but it cannot invent the
plan or finish with an unclassified inventoried operation. Next.js routes, server actions,
Pages API handlers, and Supabase mutations receive explicit authorization classifications;
`protected` and `vulnerable` results require source-line evidence. Other stacks receive
broader investigation tasks, including Firebase rules and Python server sinks.

The JSON report exposes the complete threat model, task states, validated findings,
tool-call count, and the model's final summary. This makes investigations inspectable
and gives the project a foundation for evals rather than relying on a polished chat answer.

#### Isn't the investigator itself prompt-injectable?

Yes. A malicious repository can contain comments, documentation, or strings designed
to manipulate the model reading them. `vibe-secure` does not claim prompt injection is
solved; it assumes the model may be influenced and contains what that influence can do:

- Repository text is explicitly labeled as untrusted data, never instructions.
- The model receives no shell, network, package-install, or file-write tool.
- File paths are resolved inside the scan root; traversal and sensitive credential
  files are blocked, and recognizable secrets are redacted before model access.
- Reads, returned data, and total tool calls are bounded.
- The model cannot finish while required tasks or inventoried authorization operations
  remain unclassified.
- Findings and protected/vulnerable authorization classifications must cite text that
  matches exact source lines; the final report is rendered from structured state.

These controls limit impact; they do not guarantee that a poisoned repository cannot
cause missed checks, wasted calls, or misleading task summaries. Use the offline scanner
when source code cannot be sent to a hosted model, and treat every AI-assisted result as
one review layer rather than proof that an application is secure.

## What it checks

**Agent layer (the differentiator):**
- MCP servers that pull from remote/insecure URLs — the poisoned-response vector
- MCP servers that auto-approve or auto-run actions — the zero-click path
- Editor settings that let the agent execute commands without human approval
- Secrets committed inside MCP/agent config
- Whether the project has an agent rules file with real security directives
- DuneSlide patch advisory when Cursor config is present

**App layer (table stakes):**
- Hardcoded secrets (Stripe, OpenAI, AWS, GitHub, Google, Slack, private keys)
- `.env` files tracked by git
- Server keys leaked behind public prefixes (`NEXT_PUBLIC_`, `VITE_`, …), while
  correctly ignoring keys meant to be public (publishable, anon)
- Risky patterns: `dangerouslySetInnerHTML`, `eval`, shell exec, `$where`,
  wildcard CORS, wide-open Firebase/Firestore rules
- `npm audit` / `pip-audit` when a project is detected

**Authorization investigation (AI-assisted):**
- Inventories Next.js App Router endpoints, Pages API handlers, and server actions
- Inventories Supabase mutations found outside those route handlers
- Requires each operation to be classified as protected, vulnerable, not verified,
  or not applicable
- Supports multi-file evidence across routes, middleware, services, and policy files
- Reports protected, vulnerable, and unverified operation counts separately

## Why the agent layer matters

See [`docs/agent-security.md`](docs/agent-security.md) for the threat model:
why prompt injection is structurally unfixable at the model layer, and why the
security value has to accrue in the containment layer around the agent instead.

## Development

```bash
git clone https://github.com/rikansal-alt/vibe-secure
cd vibe-secure
pip install -e ".[dev]"
pytest
```

The package uses a `src/` layout; tests run against the installed package (or via
the `pythonpath` set in `pyproject.toml`).

## Limitations

The deterministic scanner catches common mechanical mistakes in source and
configuration. The investigation agent also looks for authorization design errors,
including missing route guards, ownership checks, role boundaries, and database
policies. Authorization analysis is evidence-based but heuristic: dynamic route
registration, framework conventions outside the supported inventory, and complex
business rules can still be missed or remain unverified. The tool does not execute
your application or coding agent, although dependency checks may invoke `npm audit`
or `pip-audit`. Treat the result as a fast review layer, not proof that an application
is secure.

MIT licensed. Issues and PRs welcome.
