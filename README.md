# @shomra/agent

**Adversarial assurance for AI agents**, as a local-first CLI. It sits inside
your coding agent and CI and blocks dangerous tool-calls, shell commands and
data exfiltration *before they run* - on your machine, even offline. Enrolled,
it also attacks your org’s own guardrails (`shomra admin redteam`) and turns
each breach into a false-positive-gated control (`shomra harden`). It also vets AI
artifacts (MCP configs, Skills, slash commands, hooks, rules files) before they
install. Start with a free on-machine scan - no signup.

Zero dependencies - Node ≥ 18 built-ins only.

## Install

Also available as a [Dev Container Feature](devcontainer-feature/) (the guard
exists before the first keystroke in Codespaces / Gitpod / a local rebuild) and a
[GitHub Action](action.yml).

**There is no `curl … | sh` installer, deliberately.** Shomra's own Tier-0 guard
blocks piping a downloaded script into a shell, and the rules block it writes
tells coding agents never to do it. Shipping that one-liner would be the product
contradicting its own control in its own README.

```bash
npm i -g @shomra/agent      # global `shomra`
# or run without installing:
npx @shomra/agent gate .mcp.json
```

## Auth (optional)

Shomra is **local-first** - there is no built-in backend and no telemetry. `gate`,
`check`, `models`, `secrets`, and the runtime firewall all run fully on your
machine with no key and no network. You only connect to a Shomra org to layer on
your **org policy**, cloud/deep scans, AI fixes, and the Model Security Index.

- **Dev machine:** `shomra init --key shm_live_… --url https://shomra.your-co.com` (writes `~/.shomra/config.json`).
- **CI / headless:** set env vars instead - no `init` needed:
  - `SHOMRA_API_KEY` - your org key
  - `SHOMRA_URL` - your backend URL

Without either, every backend-only feature degrades cleanly to the on-machine result.

## Quickstart

```bash
shomra check                           # "is my repo safe?" - gate every AI artifact at once
shomra check --staged                  # only what's git-staged (pre-commit / editor-on-save)
shomra check --fix                     # gate, then remediate what isn't clean, in place
shomra fix .mcp.json --apply           # AI-fix one artifact and write it back
shomra why .mcp.json                   # why each finding matters + is-it-a-false-positive
shomra install-precommit               # block risky staged AI artifacts on git commit
shomra install-hook --agent claude     # wire the runtime firewall into Claude Code
shomra rules --write                   # teach the agent what gets blocked, so it never writes it
shomra mcp install                     # let the agent gate its own content BEFORE writing it
shomra scan                            # discover AI tooling on this machine
shomra status                          # config + firewall health
shomra help                            # full command list
```

`check`, `fix` and `why` are the verbs a developer lives in - everything below is
CI, governance, or one-time setup. Findings carry a **file:line**, so `check --json`
drives precise editor squiggles and `why`/`fix` point at the exact offending line.

- **`check`** is the developer front door: it finds every AI artifact in the tree
  (MCP configs, Skills, slash commands, hooks, rules files) and gates them in one
  shot, **local-first** - a real on-machine verdict with no backend or key, org
  policy layered on when enrolled. It's `gate --all` with dev ergonomics
  (`--staged` / `--changed` scoping, `--fix`, clean `--json` for an IDE extension).
- **`fix`** generates a minimal fix for what the gate flags and (with `--apply`)
  writes it back to your working tree - the fix is produced on the platform with
  your org's AI key, so no provider key sits on the dev machine. Nothing is
  committed or pushed. Without AI on the server it prints deterministic guidance.

### The install-time verbs (still here)

```bash
shomra gate my-skill/SKILL.md          # vet ONE artifact (auto-classified from the path)
shomra gate --all .                    # vet every AI artifact in the repo (the CI form)
```

### Starting a new agent project

```bash
shomra new agent triage-bot            # a project that starts compliant
```

Guard enforcing on every model call, an egress allowlist in code rather than in
the prompt, untrusted input kept out of the system prompt, secrets referenced
from the environment, and the gate wired into CI - from commit zero. Remediating
a project into this shape later means changing decisions that have already been
built on.

## `gate` in CI

`gate`/`gate --all` are **local-first**: real static analysis (dangerous shell,
prompt injection, secrets, exfil sinks, over-permissioned tool grants,
install-lure prose) runs on-machine, so you get a genuine verdict even if the
backend is unreachable. When enrolled + reachable, your **org policy** is layered
on top.

**Exit codes** (one convention across every command):

| Code | Meaning |
|------|---------|
| `0` | clean / pass |
| `1` | hard fail - BLOCK, vulnerable model, secret found, FAIL verdict, below `--min`, regression (also `--strict` + backend outage) |
| `2` | soft fail - FLAG under `--strict` (REVIEW when strict) |
| `3` | usage / config error - not configured, bad flags, unknown command |

**Backend outage:** by default it falls back to the on-machine verdict (org
policy not applied). `--strict` fails closed (exit 1) because org policy can't be
verified. Every backend call is bounded by `SHOMRA_API_TIMEOUT_MS` (default 30s),
so a job never hangs.

### GitHub Actions - the reusable action

```yaml
- uses: actions/checkout@v4
- uses: shomra-org/agent@v0
  with:
    args: check           # --strict is appended unless fail-on-flag: 'false'
    api-key: ${{ secrets.SHOMRA_API_KEY }}   # optional - the gate is local-first
    url: ${{ secrets.SHOMRA_URL }}
```

Wire it as a **required status check** on a protected branch and it becomes the
un-bypassable control on GitHub.com, which has no server-side hooks. On
self-hosted Git and GitHub Enterprise, `shomra install-precommit --pre-receive`
(below) refuses the push itself.

The hand-written workflow below still works and shows what the action does.

### GitHub Actions - by hand

```yaml
name: Shomra AI-artifact gate
on: [pull_request]
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - name: Vet AI artifacts
        env:
          SHOMRA_API_KEY: ${{ secrets.SHOMRA_API_KEY }}
          SHOMRA_URL: ${{ secrets.SHOMRA_URL }}
        run: npx @shomra/agent gate --all . --strict
```

CI provider, repo, branch and commit are auto-detected and recorded, so security
sees local-vs-CI gate activity in the dashboard.

### GitHub PR reviewer - inline annotations (`shomra pr`)

`shomra pr` is a richer PR-native path: on a `pull_request` it gates only the AI
artifacts **changed vs the base branch** and posts a **GitHub Check Run with
inline annotations** on the offending lines - no GitHub App or extra backend
required, just the workflow's `GITHUB_TOKEN`. Scaffold it in one shot:

```bash
npx @shomra/agent pr --init      # writes .github/workflows/shomra.yml (--force to overwrite)
```

The generated workflow:

```yaml
name: Shomra AI Security
on: pull_request
permissions:
  contents: read
  checks: write            # required to post the check-run
jobs:
  shomra:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }   # need the base ref to diff changed artifacts
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx @shomra/agent pr
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SHOMRA_API_KEY: ${{ secrets.SHOMRA_API_KEY }}   # optional - applies org policy
          SHOMRA_URL: ${{ secrets.SHOMRA_URL }}           # optional - your backend
```

The check-run **conclusion** mirrors the gate: `failure` on any BLOCK, `neutral`
on FLAG (or `failure` with `--strict`), `success` when clean. `--dry-run`/`--json`
print the computed check-run without posting. Without `SHOMRA_API_KEY` it still
runs local-first; with a key, your **org policy** (below) drives the verdict.

### SARIF - native code-scanning annotations

`gate`/`gate --all`/`check` accept `--sarif` to emit SARIF 2.1.0, which GitHub
(and GitLab) render as inline code-scanning annotations without a custom parser:

```yaml
      - run: npx @shomra/agent check . --sarif > shomra.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: shomra.sarif }
```

`shomra pr` accepts it too: bare `--sarif` writes SARIF to stdout,
`--sarif=shomra.sarif` writes a file alongside the normal check-run output.

### Org policy + triage on top of CI

When enrolled, the same **org policy** that governs the dashboard decides the CI
verdict (worst-wins across your org + project rules), so a build blocks on the
policies you defined - not just a fixed severity threshold. Two things follow:

- **Findings you've triaged away don't re-block the build.** If a security owner
  has **accepted the risk** or **ignored** a finding in the platform, the gate
  records the policy hit for transparency but no longer counts it toward
  BLOCK/FLAG. Matching is per file+line and survives across scan sources, and an
  accepted-risk that has **expired** re-blocks automatically.
- **Mandatory guardrails are exempt** - a finding that trips a policy marked
  *mandatory* still blocks even if someone accepted the risk. Use a policy
  exception for those.

### GitLab CI

```yaml
shomra-gate:
  image: node:20
  script:
    - npx @shomra/agent gate --all . --strict
  variables:
    SHOMRA_API_KEY: $SHOMRA_API_KEY
    SHOMRA_URL: $SHOMRA_URL
```

### pre-receive (server-side, cannot be skipped)

```bash
shomra install-precommit --pre-receive /srv/git/your-repo.git
```

A pre-commit hook is a courtesy: it lives on the developer's machine, it is one
`--no-verify` away, and a machine that never ran `install-precommit` has no gate
at all. A pre-receive hook runs on the **server**, on every push, for every
developer. Same check; the difference between a reminder and a control.

It **fails closed** - the opposite of the client hook. Blocking a local commit
because a binary is missing is hostile; waving a push through for the same reason
makes deleting the binary the bypass.

Available on self-hosted Git (GitLab, Gitea, Bitbucket DC, plain bare repos) and
GitHub Enterprise. GitHub.com does not run server-side hooks - use the action as
a required status check instead.

### pre-commit (local, blocks risky artifacts before they land)

`.git/hooks/pre-commit` (or a [pre-commit](https://pre-commit.com) `local` hook):

```bash
#!/usr/bin/env bash
# Gate only the AI artifacts that changed in this commit.
git diff --cached --name-only --diff-filter=ACM \
  | grep -Ei '(\.mcp\.json|SKILL\.md|CLAUDE\.md|AGENTS\.md|\.cursorrules|/\.claude/(commands|agents)/.*\.md|/\.claude/settings(\.local)?\.json)$' \
  | while read -r f; do
      npx @shomra/agent gate "$f" || exit 1
    done
```

Add `--json` anywhere to get machine-readable output for custom reporting.

## Runtime firewall

`shomra install-hook [--agent claude|cursor|windsurf|gemini|codex|copilot|cline|aider|all]`
wires Shomra into a coding agent's own hooks. It is **tiered**: catastrophic tool
calls (`curl|sh`, reverse shells, base64 RCE, live secrets, injection) are
blocked on-machine with zero network; only policy-relevant calls escalate to the
backend, behind a short timeout + circuit breaker - so a slow or down backend
never freezes the agent. Fail-open by default; `SHOMRA_GUARD_STRICT=1` fails
closed on the server tier.

Three channels are screened:

| Channel | Hook | What it stops |
|---|---|---|
| **Tool call** | PreToolUse / `beforeShellExecution` | the shell command, artifact write or MCP call, before it runs |
| **Tool result** | PostToolUse / `afterMCPExecution` | injection, exfil sinks and hidden payloads in what a fetch/read brings *back* |
| **Prompt** | `UserPromptSubmit` (Claude Code) / `beforeSubmitPrompt` (Cursor) | what **you** paste, before it leaves the machine |
| **Plan** | `PreToolUse` on `ExitPlanMode` (Claude Code) | nothing - it *informs*. See [`shomra plan`](#shomra-plan--threat-model-what-the-agent-is-about-to-build) |

The prompt channel is the one a person controls, and the only one where the leak
is a paste rather than a tool call. A live credential in a prompt is refused;
pasted text that reads as an instruction to an agent is passed through but
flagged **to the model** as untrusted data rather than blocked - you meant to
send it, the risk is that you did not read it. Backtick-quoted payloads are
down-ranked, so asking *why does `<pattern>` get flagged* is never blocked.
`SHOMRA_PROMPT_GUARD_OFF=1` disables just this channel. Only the two vendors with
a documented pre-submit hook that can stop a submission are wired; the rest get
nothing rather than a guessed event name that would silently never fire.

## Prevention: get in front of the model

Everything above intercepts *after* the model has written something. These run
before it.

```bash
shomra design docs/rfc.md  # threat-model a system that does not exist yet
shomra add model owner/m   # vet anything before it lands on the machine
shomra rules --write       # teach the agent what gets blocked here
shomra rules --check       # CI: fail when the block goes stale
shomra mcp install         # let the agent gate its own content before writing it
```

### `shomra design` - threat-model the ticket, not the repo

Every other command needs an artifact. This one reads a **description** - an RFC,
a design doc, a Jira/Linear ticket, a PR body - and answers the only question
worth asking before anyone writes code: does the thing being described hand an
attacker a path from untrusted input to a consequence?

```bash
shomra design docs/rfc-042.md
shomra design docs/ --strict                       # every design doc, fail on any closed path
gh issue view 42 --json body -q .body | shomra design -
shomra design docs/rfc-042.md --checklist | gh issue comment 42 -F -
```

It uses the platform's own model: capabilities split into **sources** (untrusted
input, sensitive data, filesystem) and **sinks** (network egress, execution,
destructive action). A closed source→sink pair is an attack path. That model does
not care whether the capabilities came from a scan or from a sentence - here they
come from a sentence, and each one cites the line that evidenced it so you can
disagree with the machine's reading.

`--checklist` emits the conditions as a markdown task list, which is the form
anyone actually acts on: paste it into the ticket as acceptance criteria.

> **It reads prose, so it sees only what was written down.** There is deliberately
> no clean verdict. `NOT_DESCRIBED` means the document did not describe
> capabilities in a way this matched - it is **not** a statement that the system
> has none. A threat model that reads as a clean bill of health is worse than
> none, because it is consumed exactly when the design is still cheap to change.

Exit codes: `1` when untrusted input reaches execution or a destructive action
(the shape where the attacker picks the action), `2` for any other closed path
under `--strict`.

### `shomra plan` - threat-model what the agent is about to build

`design` reads a document a human remembered to write. Coding agents produce a
**plan** before every non-trivial task, constantly and automatically, and nothing
looks at it. Same analysis, a hundred times the frequency, zero human effort.

The loop: agent proposes a plan → Shomra threat-models it → the controls land in
the agent's context **before it writes line one**. The agent builds the guarded
version first, instead of building the unguarded one and having the firewall
refuse it three tool calls later.

Three ways in, deliberately redundant, strongest first:

1. **`shomra_review_plan`** - an MCP tool, so any MCP-capable agent can call it
   mid-task with no vendor hook. Register it with `shomra mcp install`.
2. **The rules block asks the agent to call it.** Once the MCP server is
   registered, `shomra rules --write` adds a *Before you implement a plan*
   section - so `mcp install` and `rules --write` compose into a closed loop.
3. **A Claude Code `PreToolUse` hook on `ExitPlanMode`**, wired by
   `install-hook`. Zero-effort, but that tool name is not in the published hook
   docs, so it is the optional path and never the only one.

```bash
shomra plan plan.md            # or: … | shomra plan -
```

**A plan is a proposal, so the default is to inform, never refuse.** Denying a
plan spends a turn and tells the model only that it was wrong, not how - the
controls are the useful payload. Only untrusted-input-reaches-a-hard-sink
escalates to *ask*, and only under `SHOMRA_GUARD_STRICT=1`.
`SHOMRA_PLAN_GUARD_OFF=1` disables just this channel.

### `shomra corpus` - screen the index, not the retrieval

The result firewall screens what a retrieval brings *back*. Nothing screened what
went **in** - so a poisoned document sits in the vector store indefinitely,
clean-until-retrieved, and is judged for the first time at the worst possible
moment: as one chunk, stripped of its document, inside a request a user is
waiting on.

Index time wins on all three counts. The whole document is present, so a payload
split across paragraphs is visible. The cost is paid once per document instead of
once per retrieval. And a document that fails is simply never embedded - a
control rather than a detection.

```bash
shomra corpus ./kb --manifest .shomra/corpus.json
```

```
  ✗ QUARANTINE escalation.md
    HIGH     Injected instruction: "ignore all previous" (line 243 · chunk 19)
  ✗ QUARANTINE hidden.md
    CRITICAL Invisible / bidirectional characters
  ⚠ 2 files could not be read - they are NOT covered by the result above:
      2 × binary format - no text extractor
```

Findings carry the **chunk index**, not just the line, because retrieval returns
chunks and the chunk is what actually reaches the model. The manifest is the
point of the command: feed it to your ingestion job so a quarantined document is
never embedded.

> **Absence accounting is load-bearing.** Real corpora are mostly PDF, DOCX and
> PPTX - formats this cannot read. A screen that silently skips them and prints
> "clean" is a lie about the majority of the corpus, so every unreadable file is
> counted and reported next to the verdict, and `--strict` fails on them:
> *we could not check it* is not *it is fine*.

Fenced code blocks are down-ranked - a docs corpus is full of examples, and an
example is not a live instruction. A directive in prose is the real threat and
survives the down-rank.

### `shomra add` - vet at acquisition, not after

`mcp add` gated one channel. An agent acquires from four, and the other three had
no gate at all: a skill copied out of a gist, a model pulled from the Hub, a
package installed because an agent suggested the name.

```bash
shomra add mcp files npx -y @modelcontextprotocol/server-filesystem /tmp
shomra add skill ./downloaded-skill      # manifest AND the scripts it bundles
shomra add model openai-community/gpt2   # against the Model Index, before any weights download
shomra add package langchian --type pypi # → BLOCK: 2 edits from langchain
```

One verdict vocabulary (ALLOW / FLAG / BLOCK), one exit-code contract, `--force`
to override a BLOCK deliberately rather than by accident. After something lands
the question changes from *should we take this?* to *is it safe to remove?*,
which is a much worse question to be asked.

**Unknown is never clean.** An unreachable Model Index, an unscanned model, and a
package the AI catalog does not recognise all return **FLAG**, not ALLOW -
"we could not check" and "it is fine" are different answers.

**`shomra rules`** compiles what Shomra actually enforces - plus what *this repo*
already trips, plus your org's policy when enrolled - into the agent's own
context files:

| Agent | File |
|---|---|
| Claude Code | `CLAUDE.md` |
| Codex CLI (and the cross-vendor default) | `AGENTS.md` |
| Cursor | `.cursor/rules/shomra.mdc` |
| GitHub Copilot | `.github/copilot-instructions.md` |
| Gemini CLI | `GEMINI.md` |
| Windsurf | `.windsurfrules` |
| Cline | `.clinerules/shomra.md` |

It writes inside a `<!-- BEGIN SHOMRA MANAGED BLOCK -->` marker pair and **never
touches a line outside it**, so your own rules are safe and re-running is a
no-op. The block is derived, not boilerplate: sections switch on according to
what the repo holds (MCP configs, skills, model loads, agent-calling code), and
an **"Already present in this repo"** section names the findings a local gate
pass actually found, with paths. Commit the result and keep it honest with
`shomra rules --check`, which exits 1 when the block is missing or stale.

The generated block is itself an AI rules file, so `shomra rules` gates its own
output and refuses to write anything its own checker would block.

**`shomra mcp install`** registers Shomra *as* an MCP server with your agents, so
the model can call it in its own loop - most usefully `shomra_review_change`,
which takes proposed file content plus its intended path and returns a verdict
**without writing anything to disk**. A BLOCK there costs nothing; the same
content on disk costs a blocked tool call and a wasted turn. `shomra_rules`,
`shomra_check`, `shomra_explain`, `shomra_fix` and `shomra_scan_models` are
exposed too. `shomra mcp serve` runs the server directly (stdio JSON-RPC) if you
prefer to wire it by hand.

## Adopting Shomra on an existing repo

A brand-new gate on a repo with history will flag things. Three layers make
adoption friction-free - all of them re-grade the artifact, so a fully
suppressed file drops to ALLOW and never fails the build:

- **`shomra baseline`** records every current finding (line-independent
  fingerprints) in `.shomra/baseline.json` - commit it so the whole team shares
  it. From then on only findings introduced *after* the baseline fail; re-run it
  to refresh after cleanups. Skip it per-run with `--no-baseline`.
- **`.shomraignore`** - a repo file of `path/glob` lines (skip the file) or
  `path/glob :: title-substring` lines (skip one finding class in those files).
  The runtime firewall honors it too, so test fixtures and detection source
  aren't withheld. Silence a single finding inline with `// shomra-ignore` (or
  `# shomra-ignore`) on the finding's line or the line above, or opt a whole
  file out with `shomra-ignore-file` in its first lines (works in JSON as a
  `"_shomra": "shomra-ignore-file"` key). `--no-suppress` ignores all of this.
- **`.shomra/policy.yml`** - policy-as-code, reviewed in PRs like any code:

  ```yaml
  block: high              # min severity that BLOCKS (critical|high|medium|low|none)
  flag: medium             # min severity that FLAGS
  allow:                   # finding-title substrings to always downgrade away
    - "IPv4 address"
  ```

  For a local verdict the repo policy fully re-grades; when the backend
  returned an org decision it can only make it *stricter* (worst-wins) - repo
  config never loosens org enforcement. `--no-policy` skips it.

## Environment variables

| Var | Purpose |
|-----|---------|
| `SHOMRA_API_KEY` | Org API key (overrides config) |
| `SHOMRA_URL` | Backend URL (overrides config) |
| `SHOMRA_API_TIMEOUT_MS` | Per-request backend timeout (default 30000) |
| `SHOMRA_AGENT` | Agent-identity handle presented to `llm-proxy` + firewall |
| `SHOMRA_GATE_CONCURRENCY` | Parallel backend calls in batch gate / model lookups (default 8, 1-32) |
| `SHOMRA_GH_TOKEN` | GitHub token for `shomra pr` (falls back to `GITHUB_TOKEN`) |
| `SHOMRA_GUARD_STRICT` | `1` = firewall fails closed on the server tier |
| `SHOMRA_GUARD_LOCAL` | `0` = disable the on-machine Tier-0 guard |
| `SHOMRA_GUARD_IGNORE` | Comma-separated file globs the runtime guard treats as known-safe (adds to `.shomraignore`) |
| `SHOMRA_GUARD_ALWAYS_ESCALATE` | `1` = send every call to the server (full telemetry, higher overhead) |
| `SHOMRA_GUARD_TIMEOUT_MS` | Firewall per-call server timeout (default 2000) |
| `SHOMRA_GUARD_BREAKER_MS` | Skip the server this long after a failure (default 30000; `0` disables) |
| `SHOMRA_LLM_PROXY_BASE` | Proxy base URL `install-hook` writes for Aider (default `http://127.0.0.1:4141/openai/v1`) |
| `SHOMRA_MODEL_GUARD` | `0` = disable the model-load screen in the PreToolUse hook |
| `SHOMRA_PROMPT_GUARD_OFF` | `1` = disable the prompt channel only (tool-call and tool-result guards stay on) |
| `SHOMRA_PLAN_GUARD_OFF` | `1` = disable the plan channel only |
| `SHOMRA_MODEL_CACHE` | `0` = disable the on-machine model-index verdict cache |
| `SHOMRA_MODEL_CACHE_TTL_MS` | Model-cache freshness window (default 7 days) |

Run `shomra help` for the full command reference.
