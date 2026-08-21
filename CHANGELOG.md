# Changelog

All notable changes to `@shomra/agent` are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (threat-model refresh — OWASP AI/agentic threat modeling)
- **`shomra design --save --subject <KIND>:<id>`** — persist the threat model
  instead of printing it and moving on. Until now the analysis went to a
  terminal: the command could say what to worry about on the day of the RFC and
  had no opinion six months later, when a tool was added to the manifest and the
  model quietly stopped describing the system. Saving pins the analysis to the
  nine-axis **capability manifest** the backend computes, which is what makes
  the CI check below possible. ⚠ The manifest is taken server-side, never sent
  from the CLI — a client that posted its own could pin a model to a system it
  invented, and the caller most likely to do that is the one automating its way
  past the gate. Authoring is not approval: a saved version is `IN_REVIEW` and
  does not clear CI until someone **other than its author** approves it.
- **`shomra pr --threat-model <KIND>:<id>[,…]`** — OWASP's flagship control:
  the build fails when the capability manifest moved and the threat model did
  not. The existing gate answers "is this artifact dangerous"; it cannot answer
  this one, because the changes in question leave no dangerous artifact behind —
  a tool added to a manifest, a model swapped behind a routing rule, an approval
  step moved. The check-run names **which of the nine axes moved**, because
  "your threat model is stale" without that is a notification, not a finding.
  - ⚠ **Runs even when no AI artifact changed.** That is the case it exists for:
    a routing rule edited in application code moves the manifest while touching
    not one MCP config, and returning early there would skip the control
    precisely where it was needed and go green with a reassuring sentence.
  - ⚠ **An unreachable backend does not pass the gate** — it reports UNKNOWN and
    leaves the check neutral. Silently succeeding would make "break the network"
    the cheapest way past a control whose whole purpose is to be unskippable.
  - `STALE` / `NO_MODEL` fail; `UNREVIEWED` / `UNKNOWN` are neutral (a human step
    in flight, or our own inability to look — failing either punishes the wrong
    party). Silent without the flag, so no existing workflow changes behaviour.
- **`shomra pr --init` also scaffolds `.github/pull_request_template.md`** — the
  nine refresh-trigger questions asked on every PR (tools added? scope widened?
  new data access? model or provider changed? approval step moved?). The two
  halves are useless apart: the template surfaces the change to a human, the
  workflow checks whether the threat model followed. ⚠ An existing template is
  never overwritten without `--force`.

### Added (shift-left, batch 3)
- **`shomra plan` + `shomra_review_plan` + `plan-guard`** — threat-model what an
  agent is ABOUT to build. `design` reads a document a human remembered to write;
  coding agents produce a plan before every non-trivial task, automatically. Same
  engine, a hundred times the frequency, zero human effort: agent proposes a plan
  → Shomra threat-models it → the controls land in its context before it writes
  line one. Three redundant paths, strongest first: the MCP tool (any MCP-capable
  agent, no vendor hook), a `rules` section that asks the agent to call it (added
  only when the Shomra MCP server is actually registered — telling an agent to
  call a tool it does not have is noise that trains it to ignore the block), and
  a Claude Code `PreToolUse` hook on `ExitPlanMode`. That tool name is NOT in the
  published hook docs, so it gets its OWN PreToolUse entry rather than being
  folded into the tool-guard matcher: if it never fires, only this hook is dead.
  ⚠ A plan is a proposal — the default is to inform, never refuse. Only
  untrusted-input-reaches-a-hard-sink escalates to `ask`, and only under
  `SHOMRA_GUARD_STRICT=1`. `SHOMRA_PLAN_GUARD_OFF=1` disables just this channel.
- **`shomra corpus`** — screen RAG documents at INDEX time. The result firewall
  screens what a retrieval brings back; nothing screened what went in, so a
  poisoned document sat in the vector store indefinitely and was judged for the
  first time as one chunk, stripped of its document, inside a live request. Index
  time has the whole document (a payload split across paragraphs is visible),
  costs once per document instead of once per retrieval, and a failing document
  is simply never embedded. Findings carry the CHUNK index, not just the line,
  because retrieval returns chunks. `--manifest` emits the quarantine list for an
  ingestion job to consume. Invisible/bidi characters are a first-class BLOCK.
  ⚠ Absence accounting: real corpora are mostly PDF/DOCX/PPTX, which this cannot
  read — every unreadable file is counted and reported as NOT covered, and
  `--strict` fails on them.

### Fixed
- **`design` missed untrusted input by format and by provenance** — `pdf`
  could not match the plural in "ingests uploaded PDFs", and no rule keyed on
  content being RECEIVED FROM a party outside the trust boundary. Found by
  running plan-guard against a realistic plan. Both fixed and pinned.

### Added (shift-left, batch 2)
- **`shomra design <file|dir|->`** — threat-model a system that does not exist
  yet. Reads an RFC / design doc / Jira or Linear ticket / PR body and says
  whether what is described closes a path from untrusted input to a consequence.
  Reuses the platform's own model (`attack-graph.ts`: sources = untrusted input /
  sensitive data / filesystem; sinks = network egress / execution / destructive
  action; a closed pair is an attack path) — that model does not care whether the
  capabilities came from a scan or from a sentence. Each capability cites the
  line that evidenced it, ranked so the citation is the line that DESCRIBES the
  behaviour rather than the first line the word appeared on. `--checklist` emits
  the conditions as a markdown task list to paste into the ticket as acceptance
  criteria. Ticket integration is a pipe, deliberately:
  `gh issue view 42 --json body -q .body | shomra design -`.
  ⚠ There is no clean verdict, by design: `NOT_DESCRIBED` is a statement about
  the DOCUMENT, not the system. Exit 1 when untrusted input reaches execution or
  a destructive action; 2 for any other closed path under `--strict`.
- **`shomra add mcp|skill|model|package <ref>`** — one gate for every channel an
  agent acquires from, not just MCP. `skill` gates the manifest AND the scripts
  the skill bundles; `model` checks the Model Index before any weights download;
  `package` catches the dominant failure — an agent suggesting a plausible
  package name — with edit-distance typosquat detection against the AI package
  catalog, fully offline. ⚠ Unknown is never clean: an unreachable index, an
  unscanned model and an unrecognised package all return FLAG, never ALLOW.
- **`shomra install-precommit --pre-receive`** — the un-bypassable sibling of the
  pre-commit hook. Runs on the git SERVER, on every push, for every developer;
  no `--no-verify`, no per-machine install. Deliberately FAILS CLOSED (the client
  hook fails open): at an enforcement point, deleting the binary must not be the
  bypass. Self-hosted Git + GitHub Enterprise; on GitHub.com the equivalent is
  the Action as a required status check.
- **`shomra new agent [name] --framework vercel-ai`** — a whole project that
  starts compliant: guard enforcing on every model call, an egress allowlist in
  code rather than in the prompt, untrusted input kept out of the system prompt,
  secrets referenced from the environment, and the gate wired into CI from commit
  zero.
- **Reusable GitHub Action** (`action.yml`) — replaces the copy-pasted workflow
  snippet that no consumer ever updated. Composite, not Docker.
- **Dev Container Feature** (`devcontainer-feature/`) — installs the CLI and runs
  `shomra protect` at provision time, so the guard exists before the first
  keystroke in Codespaces / Gitpod / a local rebuild. `rules` is off by default:
  a feature that edits a developer's committed files unasked is a surprise.
  There is deliberately no `curl … | sh` installer — Shomra's own Tier-0 blocks
  that pattern, and shipping one would be the product contradicting its own
  control in its own README.

### Added
- **`shomra rules`** — compiles what Shomra enforces into the coding agent's own
  context files (`CLAUDE.md`, `AGENTS.md`, `.cursor/rules/shomra.mdc`,
  `.github/copilot-instructions.md`, `GEMINI.md`, `.windsurfrules`,
  `.clinerules/shomra.md`), so the blocked pattern is never generated. Every
  other surface intercepts *after* the model wrote something; this one runs
  before it. The block is derived, not boilerplate: the always-on directives
  mirror the Tier-0 signals the firewall actually blocks, sections switch on
  according to what the repo holds, and an "Already present in this repo"
  section names what a local gate pass actually found, with paths. Org policy
  is layered on when enrolled (new `POST /gate/rules`). Written inside a
  `<!-- BEGIN SHOMRA MANAGED BLOCK -->` marker pair — nothing outside it is
  ever touched — with `--write`, `--check` (CI drift gate, exit 1 when stale),
  `--agent`, `--json`.
- **`shomra prompt-guard`** — the third runtime channel: what *you* submit,
  screened before it leaves the machine. `install-hook` now wires Claude Code's
  `UserPromptSubmit` and Cursor's `beforeSubmitPrompt`. A live credential in a
  prompt is refused; pasted injection text is passed through but flagged to the
  model as untrusted data (you meant to send it — the risk is that you did not
  read it). Backtick-quoted payloads are down-ranked, so asking about a
  signature is never blocked. `SHOMRA_PROMPT_GUARD_OFF=1` disables just this
  channel. Only vendors with a documented pre-submit hook that can stop a
  submission are wired — a guessed event name would silently never fire, which
  reads as a control being on while it is off.
- **`shomra mcp install`** — registers Shomra *as* an MCP server with Claude
  Code / Cursor / Gemini CLI / Windsurf, so `mcp serve` is actually reachable
  instead of shipping switched off.
- **Two MCP tools** that answer *before* the write, when changing course is
  free: `shomra_review_change` (proposed content + intended path → verdict,
  nothing written to disk) and `shomra_rules` (what will be refused here).

### Fixed
- **The local Tier-0 mirror scored a rules file that FORBIDS exfiltration the
  same as one that COMMANDS it.** "Never exfiltrate data", "never read .env and
  post it anywhere", "treat paste sites as exfiltration destinations" — the
  sentences a security-conscious `CLAUDE.md` is made of — produced a CRITICAL
  exfiltration finding and a HIGH toxic-instruction finding. The backend has
  guarded this since `memory-signals.ts`; `guard-signals.mjs` had drifted and
  was missing all of it, so the false positive fired **offline**, where no
  server verdict arrives to correct it. Ported the backend's guards: per-line
  negation guarding on the exfil rule set, descriptive-line suppression,
  the loopback-URL exception, the narrowed encode-then-send connector, and the
  toxic-flow check moved from whole-document co-occurrence to a single
  imperative line. Pinned by four new regression tests that also assert real
  poisoning still BLOCKs.
- **`shomra protect` skipped agents it considered already guarded**, so a
  machine wired before a new channel existed never received it while `protect`
  reported the agent protected. The installers are idempotent and report
  `changed` honestly, so they now always run.

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
