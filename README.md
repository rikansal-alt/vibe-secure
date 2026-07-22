# vibe-secure

**A first security review for solo founders building with AI.**

I built `vibe-secure` after repeatedly reviewing vibe-coded applications for
solo founders and finding the same high-impact mistakes: exposed secrets,
unprotected operations, missing ownership checks, open database rules, and
overly permissive coding-agent configuration.

These problems are easy to introduce when an AI-generated application works
functionally but nobody has reviewed its trust boundaries. Most solo founders
do not have a security team, and much of the existing security tooling assumes
more security expertise than they have.

`vibe-secure` turns the first pass of that review into an accessible tool. The
deterministic scanner catches common mechanical mistakes without an API key.
The optional investigation agent inventories sensitive operations and examines
authentication, authorization, ownership checks, and agent configuration using
bounded, evidence-backed tools.

It is not a penetration test or proof that an application is secure. It is
designed to catch glaring, preventable issues before a founder ships them.

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

The deterministic `scan` and `agent` commands are free, require no hosted model
or API key, and are implemented with the Python standard library. Their local
checks work offline; optional `npm audit` and `pip-audit` dependency checks may
use the network. They exit non-zero on high-severity findings, so they drop into CI.

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
Without a key, use `vibe-secure scan .` for the deterministic ruleset.

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
plan or finish with an unclassified inventoried operation. Statically discoverable Next.js
routes, server actions, Pages API handlers, and Supabase mutations receive explicit
authorization classifications;
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

**Authorization investigation (AI-assisted, Next.js/Supabase scope):**
- Inventories statically discoverable Next.js App Router endpoints, Pages API handlers,
  and server actions
- Inventories Supabase mutations found outside those route handlers
- Requires each operation to be classified as protected, vulnerable, not verified,
  or not applicable
- Supports multi-file evidence across routes, middleware, services, and policy files
- Reports protected, vulnerable, and unverified counts for inventoried operations

## Scope & confidence

| Area | Method | Scope | Confidence / limitation |
|---|---|---|---|
| Known credential formats | Deterministic regex | Stripe, OpenAI, AWS, GitHub, Google, Slack, private-key headers | High for recognized formats; generic and novel secrets can be missed |
| Public environment prefixes | Deterministic lexical check | `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `PUBLIC_` | Review signal; naming alone cannot prove runtime exposure |
| Risky APIs and configuration | Deterministic lexical/structured checks | Listed code sinks, Firebase/Firestore rules, MCP and editor configuration | Finds suspicious presence, not full exploitability or data flow |
| SQL injection | Deterministic line-scoped heuristic | Obvious request-data concatenation or direct use near a query call | Low-to-medium; not cross-file or multi-line taint analysis |
| Dependencies | External audit tools | `npm audit` when npm can audit the project; `pip-audit` when installed with `requirements.txt` | Depends on lockfiles, tool availability, connectivity, and advisory data |
| Authorization design | AI-assisted structured investigation | Inventoried Next.js routes, Pages API handlers, server actions, and Supabase mutations | Evidence-backed but heuristic; inventory and classifications can be incomplete or wrong |
| Other frameworks/business logic | General investigation tasks only | Firebase and Python receive review tasks, not endpoint-level authorization inventory | No authorization-coverage claim |

“Authorization coverage” in reports means coverage of operations the current inventory
found—not coverage of every reachable operation or business rule in the application.

## Why the agent layer matters

Application code is only part of the surface. AI coding tools also consume
repository content, web results, and MCP responses while holding permissions to
read files or run commands. Cursor sandbox-escape vulnerabilities
[CVE-2026-50548](https://nvd.nist.gov/vuln/detail/CVE-2026-50548) and
[CVE-2026-50549](https://nvd.nist.gov/vuln/detail/CVE-2026-50549) affected
versions before 3.0 and showed why agent containment and approval boundaries
matter alongside application security.

See [`docs/agent-security.md`](docs/agent-security.md) for the full threat model
and the limits of model-layer prompt-injection defenses.

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
