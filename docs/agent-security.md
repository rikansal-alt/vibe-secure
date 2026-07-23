# The Agent Layer: Why Scanning Your Code Isn't Enough

Every security scanner for AI-built apps checks the same thing: the code the
agent produced. Secrets, injection, insecure defaults. That's necessary. It's
also only half the surface.

## The bug that won't be fixed

In July 2026, Cato AI Labs disclosed DuneSlide: two critical vulnerabilities in
Cursor (CVE-2026-50548 and CVE-2026-50549, both CVSS 3.1: 9.8). A prompt injection —
carried not by the user but inside content the agent read on its own, a connected
MCP server's response or a page returned by a web search — escaped Cursor's
command sandbox and executed code on the machine. No link to click. No approval
box. The specific bugs were patched in Cursor 3.0. The class was not.

That's the important distinction. You can patch a sandbox-escape path. You cannot
patch the reason it worked.

## Why prompt injection is structural

A language model reads instructions and data as one undifferentiated stream of
tokens. When your agent ingests an MCP response or a web page, the model has no
reliable, built-in boundary between "this is content to summarize" and "this is a
command to obey." To the model, they're the same kind of thing.

This is why DuneSlide was not the first flaw of its shape and won't be the last:
similar prompt-injection and sandbox-escape issues have surfaced across AI coding
tools, because the underlying confusion is shared. It's not one vendor being
careless. It's the architecture.

There is no parameterized-query moment coming for prompt injection — no single
fix that makes the model reliably separate instructions from data, the way
parameterized queries ended most SQL injection. The confusion is baked into how
the models work.

## Where the security value has to accrue instead

If you can't fix it at the model layer, the value moves outward — to the layer
around the agent:

- **Containment.** Assume the agent will eventually be tricked. Limit what a
  tricked agent can reach.
- **Permission scoping.** No standing write access to system paths, startup
  files, or credentials the task doesn't need.
- **Trust boundaries on inputs.** Treat every MCP response and web result the
  agent consumes as untrusted, because that's exactly where the injection rides.
- **Human-in-the-loop for irreversible actions.** The DuneSlide exploit needed
  no click precisely because auto-run removed the human. Put the human back for
  anything that writes, deletes, or executes.
- **Egress control.** A contained agent that can't phone home can't exfiltrate.

## What vibe-secure checks, and what it doesn't

vibe-secure scans the *static configuration* of this layer: which MCP servers you
trust, whether they auto-approve, whether your editor lets the agent run commands
unattended, whether you've written the agent any rules. That's the cheap,
common, high-impact set.

It does not run your agent, simulate an injection, or verify runtime containment.
Those are the harder problems — and, not coincidentally, where this whole space
is heading next. Static config hygiene is the floor, not the ceiling.
