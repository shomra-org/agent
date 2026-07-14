# @shomra/agent

The Shomra AI-security CLI. Discovers the AI tooling on a machine, vets AI
artifacts (MCP configs, Skills, slash commands, hooks, rules files) before they
install, and enforces a runtime firewall around coding agents and LLM traffic.

Zero dependencies — Node ≥ 18 built-ins only.

## Install

```bash
npm i -g @shomra/agent      # global `shomra`
# or run without installing:
npx @shomra/agent gate .mcp.json
```

## Auth (optional)

Shomra is **local-first** — there is no built-in backend and no telemetry. `gate`,
`check`, `models`, `secrets`, and the runtime firewall all run fully on your
machine with no key and no network. You only connect to a Shomra org to layer on
your **org policy**, cloud/deep scans, AI fixes, and the Model Security Index.

- **Dev machine:** `shomra init --key shm_live_… --url https://shomra.your-co.com` (writes `~/.shomra/config.json`).
- **CI / headless:** set env vars instead — no `init` needed:
  - `SHOMRA_API_KEY` — your org key
  - `SHOMRA_URL` — your backend URL

Without either, every backend-only feature degrades cleanly to the on-machine result.

## Quickstart

```bash
shomra check                           # "is my repo safe?" — gate every AI artifact at once
shomra check --staged                  # only what's git-staged (pre-commit / editor-on-save)
shomra check --fix                     # gate, then remediate what isn't clean, in place
shomra fix .mcp.json --apply           # AI-fix one artifact and write it back
shomra why .mcp.json                   # why each finding matters + is-it-a-false-positive
shomra install-precommit               # block risky staged AI artifacts on git commit
shomra install-hook --agent claude     # wire the runtime firewall into Claude Code
shomra scan                            # discover AI tooling on this machine
shomra status                          # config + firewall health
shomra help                            # full command list
```

`check`, `fix` and `why` are the verbs a developer lives in — everything below is
CI, governance, or one-time setup. Findings carry a **file:line**, so `check --json`
drives precise editor squiggles and `why`/`fix` point at the exact offending line.

- **`check`** is the developer front door: it finds every AI artifact in the tree
  (MCP configs, Skills, slash commands, hooks, rules files) and gates them in one
  shot, **local-first** — a real on-machine verdict with no backend or key, org
  policy layered on when enrolled. It's `gate --all` with dev ergonomics
  (`--staged` / `--changed` scoping, `--fix`, clean `--json` for an IDE extension).
- **`fix`** generates a minimal fix for what the gate flags and (with `--apply`)
  writes it back to your working tree — the fix is produced on the platform with
  your org's AI key, so no provider key sits on the dev machine. Nothing is
  committed or pushed. Without AI on the server it prints deterministic guidance.

### The install-time verbs (still here)

```bash
shomra gate my-skill/SKILL.md          # vet ONE artifact (auto-classified from the path)
shomra gate --all .                    # vet every AI artifact in the repo (the CI form)
```

## `gate` in CI

`gate`/`gate --all` are **local-first**: real static analysis (dangerous shell,
prompt injection, secrets, exfil sinks, over-permissioned tool grants,
install-lure prose) runs on-machine, so you get a genuine verdict even if the
backend is unreachable. When enrolled + reachable, your **org policy** is layered
on top.

**Exit codes:** `0` = allowed · `1` = blocked (or `--strict` + backend outage) · `2` = flagged with `--strict`.

**Backend outage:** by default it falls back to the on-machine verdict (org
policy not applied). `--strict` fails closed (exit 1) because org policy can't be
verified. Every backend call is bounded by `SHOMRA_API_TIMEOUT_MS` (default 30s),
so a job never hangs.

### GitHub Actions

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

### GitHub PR reviewer — inline annotations (`shomra pr`)

`shomra pr` is a richer PR-native path: on a `pull_request` it gates only the AI
artifacts **changed vs the base branch** and posts a **GitHub Check Run with
inline annotations** on the offending lines — no GitHub App or extra backend
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
          SHOMRA_API_KEY: ${{ secrets.SHOMRA_API_KEY }}   # optional — applies org policy
          SHOMRA_URL: ${{ secrets.SHOMRA_URL }}           # optional — your backend
```

The check-run **conclusion** mirrors the gate: `failure` on any BLOCK, `neutral`
on FLAG (or `failure` with `--strict`), `success` when clean. `--dry-run`/`--json`
print the computed check-run without posting. Without `SHOMRA_API_KEY` it still
runs local-first; with a key, your **org policy** (below) drives the verdict.

### SARIF — native code-scanning annotations

`gate`/`gate --all`/`check` accept `--sarif` to emit SARIF 2.1.0, which GitHub
(and GitLab) render as inline code-scanning annotations without a custom parser:

```yaml
      - run: npx @shomra/agent check . --sarif > shomra.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: shomra.sarif }
```

### Org policy + triage on top of CI

When enrolled, the same **org policy** that governs the dashboard decides the CI
verdict (worst-wins across your org + project rules), so a build blocks on the
policies you defined — not just a fixed severity threshold. Two things follow:

- **Findings you've triaged away don't re-block the build.** If a security owner
  has **accepted the risk** or **ignored** a finding in the platform, the gate
  records the policy hit for transparency but no longer counts it toward
  BLOCK/FLAG. Matching is per file+line and survives across scan sources, and an
  accepted-risk that has **expired** re-blocks automatically.
- **Mandatory guardrails are exempt** — a finding that trips a policy marked
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
backend, behind a short timeout + circuit breaker — so a slow or down backend
never freezes the agent. Fail-open by default; `SHOMRA_GUARD_STRICT=1` fails
closed on the server tier.

## Environment variables

| Var | Purpose |
|-----|---------|
| `SHOMRA_API_KEY` | Org API key (overrides config) |
| `SHOMRA_URL` | Backend URL (overrides config) |
| `SHOMRA_API_TIMEOUT_MS` | Per-request backend timeout (default 30000) |
| `SHOMRA_AGENT` | Agent-identity handle presented to `llm-proxy` + firewall |
| `SHOMRA_GUARD_STRICT` | `1` = firewall fails closed on the server tier |
| `SHOMRA_GUARD_LOCAL` | `0` = disable the on-machine Tier-0 guard |
| `SHOMRA_GUARD_TIMEOUT_MS` | Firewall per-call server timeout (default 2000) |
| `SHOMRA_GUARD_BREAKER_MS` | Skip the server this long after a failure (default 30000; `0` disables) |

Run `shomra help` for the full command reference.
