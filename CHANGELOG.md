# Changelog

All notable changes to `@shomra/agent` are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-07-27

### Changed (breaking)
- **One exit-code convention across every command**: `0` = clean/pass, `1` =
  hard fail (BLOCK, vulnerable model, secret found, FAIL verdict, below
  `--min`, regression), `2` = soft fail (FLAG under `--strict`), `3` =
  usage/config error (not configured, bad flags, unknown command). Previously
  five conventions coexisted; notably `report`/`scan-zip`/`model-scan`/
  `memory-scan`/`redteam`/`campaign` used `2` for hard fails (now `1`), and
  `provenance` with no backend exited `0` (now `3` — a green build that proved
  nothing).
- `install-hook` now writes an **absolute hook invocation**
  (`"<node>" "<path to shomra.mjs>" tool-guard …`) instead of the bare
  `shomra tool-guard`, so hooks keep firing when the CLI was run via `npx` or
  PATH drifts. Detection/idempotency accept both the old and new forms.
- The Aider integration now points at the proxy's real route
  (`http://127.0.0.1:4141/openai/v1`); previously it wrote `/llm/openai`,
  which 404'd. The proxy also strips a legacy `/llm` prefix so already-written
  configs keep working.

### Added
- `shomra --version` / `-v` / `version` (reads package.json — single source).
- Unknown commands and unknown `--flags` now error with exit `3` and a
  "did you mean …?" suggestion instead of dumping the full help (commands) or
  silently no-opping (flags — the worst failure mode for a security gate).
- Boolean flags (`--strict`, `--json`, `--sarif`, …) no longer swallow the
  next argument: `shomra check --strict <dir>` and `shomra gate --json <file>`
  now work in any order.
- `status` reports the runtime-firewall hook per agent (all 8 supported
  agents' config files, both bare and absolute command forms) and prints
  "none (local mode …)" instead of `null` for an unconfigured backend.
- Local `check` output: clean display name (path shown once), `(path:line)`
  on findings that carry one, and an explicit "… and N more (run with --json
  for all)" instead of silent truncation at 3.
- `pr --sarif` (stdout) / `--sarif=<file>` — SARIF 2.1.0 for the changed
  artifacts, matching the platform docs.
- The gate now covers its own attack surface: the other agents' hook/config
  files install-hook writes (`.cursor/hooks.json`, `.gemini/settings.json`,
  `.cline/hooks.json`, `.codex/hooks.json`, windsurf/copilot hook files,
  `.aider.conf.yml`) are matched and checked like `.claude/settings.json`.
- `models` no longer claims "no known-vulnerable models" when lookups failed —
  it reports how many references could not be checked and why. `mcp add`
  skips the index lookup cleanly when no backend is configured (no more raw
  fetch errors).
- `--json` output of `model-scan`, `memory-scan`, `redteam`, `campaign` and
  `harden` is now pure JSON (progress chatter no longer breaks `| jq`).
- Shared "Not configured" error (exit `3`) that says where to get a key
  (app → Settings → API Keys).
- `install-precommit`'s hook now prints an unmissable warning when `shomra`
  is not on PATH (the gate did NOT run), instead of a silent skip.
- `install-hook` with no `--agent` says it defaults to Claude Code only and
  suggests `--agent all` / `shomra protect`; help lists all 8 agents.
- Help: exit-code table, `report`, `mcp list`, and the full `SHOMRA_*` env
  var set; README documents the same plus the baseline/.shomraignore/
  policy.yml adoption story.
- CLI-level tests (`tests/cli.test.mjs`): flag parsing, unknown-flag/command
  rejection, `--version`, JSON purity, and exit-code mapping.

## [0.2.x] (0.2.1 – 0.2.11)

Consolidated — these releases shipped between 0.2.0 and 0.3.0:

- `fix` (AI remediation with unified-diff preview / `--apply`) and `why`
  (per-finding explanation + false-positive read; works offline).
- `baseline` — accept current findings so only NEW ones fail; plus
  `.shomraignore`, inline `shomra-ignore` comments, and `.shomra/policy.yml`
  policy-as-code (block/flag thresholds + allow-list, worst-wins vs org).
- `provenance` — evidence-backed "which changed files did an AI agent write?"
  from runtime-firewall telemetry, with `--trailer` and `--fail-on-blocked`.
- `campaign` — autonomous multi-turn adversary runs; `harden` — the
  self-hardening flywheel (propose → FP-verify → `--apply` signatures).
- `llm-proxy` — local guard proxy for OpenAI/Anthropic/Gemini + compatible
  providers; `agent-identity register` — per-agent credentials presented as
  `x-shomra-agent`.
- `mcp serve` — Shomra as an MCP server (check / scan_models / fix / explain
  tools over stdio JSON-RPC); `mcp add` vets servers against the MCP Security
  Index before writing configs.
- `pr --init` — one-shot scaffold of the GitHub Actions PR-review workflow.
- Model-load screening in the PreToolUse hook (Model Security Index cache,
  guard-budgeted lookups), tiered Tier-0/Tier-2 guard hardening, circuit
  breaker, and multi-agent hook support (cursor/windsurf/gemini/codex/
  copilot/cline/aider).
- Relicensed to **Apache-2.0** and prepared the package for public release
  (added `LICENSE`, `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`, `.gitignore`,
  `CODEOWNERS`).

## [0.2.0]

- Local-first scanner and runtime firewall for AI artifacts (skills, slash
  commands, subagents, hooks, MCP configs, rules/instruction files, memory).
- `check` / `gate` / `gate --all` with `--json` and `--sarif` output and
  CI-friendly exit codes (0 allowed / 1 blocked / 2 flagged with `--strict`).
- `models` — detects AI-model loads in source and looks them up in the Shomra
  Model Security Index (enrichment; degrades offline).
- `install-hook` / `tool-guard` / `result-guard` — tiered runtime firewall for
  coding agents (local Tier-0 block, optional backend escalation).
- `secrets`, `doctor`, `protect`, `new`, `mcp add`, `why`, `pr` (GitHub PR bot),
  `install-precommit`.
- `discovery.mjs` machine scan for local AI tooling, runtimes, and exposed keys.
