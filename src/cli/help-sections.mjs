import { LLM_PROVIDERS } from '../commands/llm-proxy.mjs';
import { bold, cyan, dim, green } from '../core/terminal.mjs';
import { VERSION } from '../core/version.mjs';

const BANNER = () => `
${bold(cyan('Shomra'))} ${dim('- adversarial assurance for AI agents · v' + VERSION)}
`;

const USAGE = () => `${bold('USAGE')}
  shomra <command> [options]
`;

const MODES = () => `${bold('MODES')}  ${dim('- local-first: everything that can run on your machine does, with no account')}
  ${cyan('Local')}     ${dim('(no key)')}  check · gate · doctor · protect · design · plan · corpus · rules · add · secrets · models · new · mcp
                        ${dim('Fully on-machine. Nothing leaves your machine. Your lead-in - no signup.')}
  ${green('Enrolled')}  ${dim('(shm_live_)')} adds org policy, AI ${bold('fix')}/${bold('why')}, deep scans (zip/model/memory) & the dashboard
  ${green('CI')}        ${dim('(shm_ci_)')}   scoped, revocable pipeline key for ${bold('pr')} / ${bold('check')} in CI
  ${dim('Enroll with')} ${bold('shomra init --key shm_…')}${dim('; generate keys in the platform → Settings → API Keys.')}
`;

const COMMANDS = () => `${bold('COMMANDS')}
  ${dim('Daily - the verbs you live in')}
  ${cyan('check')}         ${bold('Is my repo safe?')} Gate every AI artifact  ${dim('[dir] [--staged|--changed] [--fix] [--strict] [--json]')}
  ${cyan('fix')}           Remediate an artifact in place (AI)    ${dim('<file> [--apply] [--kind …] [--json]')}
  ${cyan('why')}           Explain a finding + false-positive read ${dim('<file> [--kind …] [--json]')}
  ${cyan('gate')}          Vet ONE AI artifact before install     ${dim('<file> [--kind …] [--strict] [--json]  ·  --all for a whole repo (CI)')}
  ${cyan('scan')}          Discover AI tooling on this machine    ${dim('[--report] [--json] [--path <dir>]')}
  ${cyan('report')}        Discover + send inventory to your Shomra org ${dim('(alias: scan --report) [--json]')}
  ${cyan('status')}        Show config, enrollment + firewall health
  ${cyan('run')}           ${bold('Run a whole assurance playbook')} ${dim('<id> [--input k=v]… [--project <id>] [--json]  ·  --list for the catalog')}
                ${dim('scan → red-team → harden → compliance → gate, as one command. Exits')}
                ${dim('non-zero when a gate holds, so a pipeline can block the release.')}

  ${dim('Setup - run once per machine / repo')}
  ${cyan('init')}          Configure + enroll this machine       ${dim('--key shm_live_… [--url <backend>]')}
  ${cyan('protect')}       Wire the runtime firewall for every coding agent ${dim('[--local] [--force]')}
  ${cyan('install-hook')}  Wire the runtime firewall into ONE agent ${dim('[--agent claude|cursor|windsurf|gemini|codex|copilot|cline|aider|all] [--global]')}
  ${cyan('provenance')}    Which changed files an AI agent wrote   ${dim('[--staged | --base main] [--trailer] [--fail-on-blocked] [--json]')}
  ${cyan('install-precommit')} Gate staged AI artifacts on git commit ${dim('[dir] [--force]  ·  --pre-receive for the un-skippable server-side hook')}
  ${cyan('doctor')}        ${bold('Am I safe?')} Posture of this machine's AI setup ${dim('[--json]')}

  ${dim('Prevention - get in front of the model, not just behind it')}
  ${cyan('design')}        ${bold('Threat-model a system before it exists')} ${dim('<file|dir|-> [--save --subject KIND:id] [--checklist] [--strict] [--json]')}
                ${dim('Reads an RFC / design doc / ticket and says whether it closes a path from')}
                ${dim('untrusted input to a consequence, plus what must be true before it ships.')}
                ${dim('Pipe a ticket straight in: ')}${bold('gh issue view 42 --json body -q .body | shomra design -')}
  ${cyan('plan')}          ${bold('Threat-model what an agent is about to build')} ${dim('<file|-> [--strict] [--json]')}
                ${dim('Same engine as design, on the agent\'s own plan. Also an MCP tool')}
                ${dim('(')}${bold('shomra_review_plan')}${dim(') so every agent can call it mid-task, and a hook.')}
  ${cyan('corpus')}        ${bold('Screen RAG documents before they are indexed')} ${dim('<dir|file> [--chunk-size N] [--manifest <f>] [--strict] [--json]')}
                ${dim('A poisoned doc never enters the store. Reports the CHUNK a payload would')}
                ${dim('land in, and counts every file it could not read as NOT covered.')}
  ${cyan('add')}           ${bold('Vet anything BEFORE it lands')} ${dim('mcp|skill|model|package <ref> [--force] [--strict] [--json]')}
                ${dim('One gate for every acquisition channel an agent has.')}
  ${cyan('rules')}         ${bold('Teach the agent what gets blocked')} ${dim('[dir] [--write] [--check] [--agent claude,codex,cursor,gemini,copilot,windsurf,cline|all] [--json]')}
                ${dim('Compiles what Shomra enforces + what this repo already trips into CLAUDE.md /')}
                ${dim('AGENTS.md / .cursor/rules / copilot-instructions, inside a managed block that never')}
                ${dim('touches your own text. --check fails CI when it goes stale.')}
  ${cyan('mcp install')}   Register Shomra AS an MCP server with your agents ${dim('[--agent claude,cursor,gemini,windsurf|all] [--global]')}
                ${dim('Lets the model call ')}${bold('shomra_review_change')}${dim(' on content BEFORE it writes it.')}

  ${dim('CI & repo hygiene')}
  ${cyan('pr')}            Review a PR - inline findings on the diff ${dim('(CI) [--init] [--strict] [--dry-run]')}
  ${cyan('baseline')}      Accept current findings; only NEW ones fail ${dim('[dir]')}
  ${cyan('secrets')}       Scan working tree + git history for leaked keys ${dim('[dir] [--history] [--depth N]')}
  ${cyan('models')}        Find models the code loads + look up known vulns ${dim('[dir] [--strict] [--dry-run]')}

  ${dim('Build safely')}
  ${cyan('new')}           Scaffold a secure-by-default artifact  ${dim('skill|command|subagent|agent-card|mcp|rules [name]')}
  ${cyan('new agent')}     Scaffold a whole agent project that starts compliant ${dim('[name] [--framework vercel-ai]')}
  ${cyan('mcp add')}       Vet an MCP server, then add it to a config ${dim('<name> <command…>|--url <url> [--config <f>] [--force]')}
  ${cyan('mcp list')}      List the MCP servers in a config       ${dim('[--config <f>] [--json]')}
  ${cyan('mcp serve')}     Run Shomra AS an MCP server so agents call its checks ${dim('(review_change/rules/check/scan_models/fix/explain)')}

  ${dim('Governance & advanced')}  ${dim('→')} ${bold('shomra admin')} ${dim('for the full list')}
  ${cyan('admin')}         Deep scans, red-team, hardening, agent identity, LLM proxy
                ${dim('scan-zip · model-scan · memory-scan · redteam · campaign · harden · agent-identity · llm-proxy')}

  ${dim('(internal hook handlers, invoked by install-hook - not run by hand: tool-guard, result-guard, prompt-guard, plan-guard)')}
`;

const GATE = () => `${bold('GATE')}
  Checks an MCP config / Skill / slash command / hook / rules file BEFORE it
  lands on the machine. Exit 0 = allowed, 1 = blocked (2 = flagged with --strict)
  - wire it into pre-commit or CI. Nothing is executed; analysis is static.

  ${bold('Works offline.')} Real static analysis (dangerous shell, prompt injection,
  secrets, exfil sinks, over-permissioned tool grants, install-lure prose) runs
  ON-MACHINE, so ${bold('gate')} returns a genuine verdict with no backend and no key.
  When enrolled + reachable, the backend layers your ORG POLICY + governance on
  top. If the backend is down it falls back to the local verdict (and says so);
  ${bold('--strict')} instead fails closed (exit 1) because org policy couldn't be verified.

  ${bold('--all')} walks a repo/dir and gates every AI artifact at once - drop it in
  a CI job to fail the build on risky artifacts. CI environment (provider, repo,
  branch, commit) is auto-detected and recorded for local-vs-CI gate activity.
`;

const CHECK = () => `${bold('CHECK')}  ${dim('- the one command a developer runs')}
  ${bold('shomra check')} answers "is my repo safe?" in one shot: it finds every AI
  artifact in the tree (MCP configs, Skills, slash commands, hooks, rules files)
  and gates them together, ${bold('local-first')} - a real on-machine verdict with no
  backend or key; enrolling layers your org policy on top. It is ${bold('gate --all')}
  with dev ergonomics:
    ${dim('shomra check')}            every AI artifact under the repo
    ${dim('shomra check --staged')}   only what's git-staged  ${dim('(wire into pre-commit / on-save)')}
    ${dim('shomra check --changed')}  only what changed vs HEAD
    ${dim('shomra check --fix')}      gate, then remediate what isn't clean, in place
    ${dim('shomra check --json')}     machine-readable - what an IDE extension calls
    ${dim('shomra check --sarif')}    SARIF 2.1.0 - upload for native GitHub/GitLab PR annotations
  Exit 0 = clean, 1 = blocked, 2 = flagged with --strict.
`;

const BASELINE_AND_SUPPRESSION = () => `${bold('BASELINE & SUPPRESSION')}  ${dim('- adopt on a messy repo; silence a false positive')}
  ${bold('shomra baseline')} records the current findings as accepted (.shomra/baseline.json,
  line-independent) so only findings introduced AFTER it fail - commit it to share
  with the team. Silence individual findings three ways:
    ${dim('.shomraignore')}   a repo file: ${dim('path/glob')} (skip file) or ${dim('path/glob :: title-substring')}
    ${dim('inline comment')}  ${bold('// shomra-ignore')} / ${bold('# shomra-ignore')} on the finding's line or the one above
    ${dim('whole file')}      ${bold('shomra-ignore-file')} in the first lines (works in JSON too)
  Any suppression re-grades the artifact, so a fully-suppressed file drops to ALLOW.
  ${dim('--no-suppress')} ignores all of the above; ${dim('--no-baseline')} ignores just the baseline.
`;

const POLICY_AS_CODE = () => `${bold('POLICY-AS-CODE')}  ${dim('- team gate rules, versioned in the repo')}
  ${bold('.shomra/policy.yml')} (or .json) sets your team's thresholds, reviewed in PRs:
    ${dim('block: high')}       min severity that BLOCKS   ${dim('(critical|high|medium|low|none)')}
    ${dim('flag:  medium')}     min severity that FLAGS
    ${dim('allow: ["IPv4 address"]')}  finding titles to always downgrade
  For a local verdict the repo policy fully re-grades; when the backend returned an
  org decision it can only make it STRICTER (worst-wins). ${dim('--no-policy')} skips it.
`;

const FIX = () => `${bold('FIX')}  ${dim('- remediate without leaving your editor')}
  ${bold('shomra fix <file>')} generates a MINIMAL fix for whatever the gate flags in
  that artifact and shows it as a unified diff; ${bold('--apply')} writes it back to the
  local file. The fix is produced on the platform with your org's AI key (so no
  provider key sits on the dev machine) - enrollment is required. When the
  server has no AI configured it degrades to printing the deterministic
  remediation guidance to apply by hand. Nothing is committed or pushed; the
  edit lands in your working tree for you to review and commit.
`;

const WHY = () => `${bold('WHY')}  ${dim('- decide if a finding is real')}
  ${bold('shomra why <file>')} is the developer shape of "investigate": for each finding
  it gives a plain-English why-it-matters, a one-line exploit scenario, and an
  honest true/false-positive read - the conclusion, not a tool-call timeline.
  AI-distilled when enrolled; offline it prints the on-machine findings and their
  fixes. Use it when the gate flags something you think is a false positive.
`;

const INSTALL_PRECOMMIT = () => `${bold('INSTALL-PRECOMMIT')}
  ${bold('shomra install-precommit')} writes a ${dim('.git/hooks/pre-commit')} that runs
  ${bold('check --staged')}, so a risky MCP config / skill / rules file is caught before
  it commits. A BLOCK stops the commit; flags warn but don't. Existing hooks are
  never clobbered (it tells you the one line to add, or ${bold('--force')} replaces with
  a backup). Override a single commit with ${bold('git commit --no-verify')}.
`;

const MODEL_SCAN = () => `${bold('MODEL-SCAN')}
  Runs SAST over a public AI model's SOURCE - the custom .py files transformers
  imports under trust_remote_code and the config.json/tokenizer that bind them.
  Flags eval/exec/os.system/subprocess, pickle/torch.load deserialization,
  __reduce__ gadgets, network egress and auto_map (AutoModel/AutoTokenizer)
  usage, each with a rule id, file:line and code snippet. Weights are never
  downloaded and nothing is executed. Findings land in your Shomra dashboard.
`;

const MEMORY_SCAN = () => `${bold('MEMORY-SCAN')}
  Persistent agent memory (MEMORY.md, .claude/memory/…, mem0/letta stores) AND
  rules/instruction files (CLAUDE.md, AGENTS.md, .cursorrules, copilot-instructions,
  …) are re-fed to the model as trusted context every session - so a single
  poisoned entry (OWASP ASI06 / the MemoryTrap class) persists across sessions and
  reboots. Rules files are graded against an instruction baseline (standing
  directives are legitimate there; only hijack / conceal-from-user / staged-payload
  / exfil phrasing is poison), memory against a fact baseline. memory-scan reports
  each write (with provenance) so Shomra can track drift from an approved baseline
  and roll back a poisoned store. Once ${bold('install-hook')} is wired, the agent's own
  memory and rules-file writes are captured automatically. Analysis is static.
`;

const REDTEAM = () => `${bold('REDTEAM')}
  Replays a library of adversarial scenarios (goal hijack, indirect injection,
  system-prompt leak, data exfil, tool escalation, jailbreak, secret extraction,
  memory poisoning) against your OWN LLM Guard (in probe mode - never logged as a
  real attack) or model, scores a resilience %, and flags REGRESSIONS vs the last
  run. Authorized testing of your own stack; nothing is executed and no attack
  leaves the platform. Add ${bold('--evolve')} to turn on the evolutionary attacker: a
  population-based genetic search that breeds evasive variants (obfuscation,
  encoding, wrapping, splitting) against any scenario the fixed set can't crack,
  learning what beats YOUR guard and opening with it next time. Works with AI on
  or off. In CI, gate the pipeline with ${bold('--min <resilience>')} and/or
  ${bold('--fail-on-regression')} (exit 2 fails the build). Run it on a schedule so a model
  or policy change can't silently weaken a defense.
`;

const HARDEN = () => `${bold('HARDEN')}
  The self-hardening flywheel - turns a red-team breach into a defense. Runs a
  red-team (or reuses one with ${bold('--run <id>')}), asks Shomra to propose high-precision
  detection signatures for whatever got through, and VERIFIES each against a
  benign corpus: a candidate must catch the attack AND fire on zero legitimate
  messages, so the guard can only ever get tighter. With ${bold('--apply')} the survivors
  go live as a signature pack - no redeploy - and a confirmation re-run proves
  the resilience lift. Without AI configured it still works, mining signatures
  deterministically from the breaching prompts. Pair it with ${bold('redteam')} in CI.
`;

const AGENT_IDENTITY = () => `${bold('AGENT IDENTITY')}
  Give each non-human agent a first-class identity with a least-privilege
  capability policy - which providers/models it may call, which tools / MCP
  servers it may invoke, whether it may run shell. ${bold('agent-identity register')} mints
  its shm_agt_ credential; export ${bold('SHOMRA_AGENT')} so ${bold('llm-proxy')} and the runtime
  firewall present it, and every call is authorized against its policy at the two
  runtime chokepoints (identity axis) on top of content screening. Govern,
  approve break-glass requests, and revoke (a live kill-switch) in the dashboard
  → Agent Identities. Unknown agents are auto-discovered there for visibility.
`;

const LLM_PROXY = () => `${bold('LLM-PROXY')}
  Runs a local guard in front of your LLM providers. Point your SDK's base URL
  at it (OPENAI_BASE_URL / ANTHROPIC_BASE_URL, the Google GenAI base URL, or any
  OpenAI-compatible SDK's baseURL) - every prompt and completion is screened
  against your org's policies; violations are blocked with HTTP 403 and logged
  to the LLM Guard dashboard. Supported providers:
    ${dim(LLM_PROVIDERS.join(' · '))}
  openai + the OpenAI-compatible ones share the /<provider>/v1 path shape;
  anthropic and gemini use their own (/anthropic, /gemini).
`;

const RUNTIME_FIREWALL = () => `${bold('RUNTIME FIREWALL (multi-agent)')}
  ${bold('shomra install-hook')} wires Shomra into a coding agent's own hook system so
  it screens both channels - the pre-tool-call hook BEFORE a shell command,
  artifact write (adding an MCP/skill/command/hook/rules file), or MCP call
  runs, and the post-tool-call hook that screens content (WebFetch/Read/MCP
  responses) coming BACK into the agent's context for prompt injection, exfil
  sinks, and hidden payloads before the model acts on them.

  Default target is Claude Code (unchanged for existing installs). Add
  ${bold('--agent <name>')} (comma-separated, or ${bold('all')}) to also wire in:
    ${dim('claude')} (Claude Code) · ${dim('cursor')} (Cursor) · ${dim('windsurf')} (Windsurf/Cascade) ·
    ${dim('gemini')} (Gemini CLI) · ${dim('codex')} (OpenAI Codex CLI) · ${dim('copilot')} (GitHub Copilot CLI) ·
    ${dim('cline')} (Cline) · ${dim('aider')} (Aider - no tool hooks, so it is routed through the LLM Guard proxy)
  e.g. ${dim('shomra install-hook --agent cursor,windsurf')} or ${dim('shomra install-hook --agent all')}.
  Windsurf's post-hooks can flag/log but not withhold a result (vendor limit).

  Risky calls/results are blocked and every decision lands in Gate Activity,
  tagged with which agent triggered it.

  ${bold('Tiered enforcement (fast + unbreakable).')} The guard decides the dangerous
  majority ON-MACHINE with zero network - curl|sh, reverse shells, base64 RCE,
  live secrets, injection - so protection survives a slow, down, or blocked
  backend and adds no latency to ordinary calls. Only policy-relevant calls
  (artifact installs, MCP calls, agent-identity, network egress, or anything
  the local tier flags) escalate to the server for the full org-policy /
  identity / governance / flow engine, with a short timeout + a circuit breaker
  that skips a known-down backend. Fail-open by default (the local tier is still
  enforcing); SHOMRA_GUARD_STRICT=1 to also fail-closed on the server tier.
`;

const EXIT_CODES = () => `${bold('EXIT CODES')}  ${dim('- one convention across every command')}
  0   clean / pass
  1   hard fail - BLOCK, vulnerable model, secret found, FAIL verdict, below --min, regression
  2   soft fail - FLAG under --strict (REVIEW when strict)
  3   usage / config error - not configured, bad flags, unknown command
`;

const ENV = () => `${bold('ENV')}
  SHOMRA_API_KEY              API key (overrides config)
  SHOMRA_URL                  Backend URL (overrides config)
  SHOMRA_API_TIMEOUT_MS=30000 Per-request backend timeout for scan/gate/report (never hangs)
  SHOMRA_AGENT                Agent-identity handle presented as x-shomra-agent (llm-proxy + firewall)
  SHOMRA_GATE_CONCURRENCY=8   Parallel backend gate/model-lookup calls in batch runs (1-32)
  SHOMRA_GH_TOKEN             GitHub token for \`shomra pr\` (falls back to GITHUB_TOKEN)
  SHOMRA_GUARD_STRICT=1       Fail-closed on the server tier if the backend is unreachable
  SHOMRA_GUARD_LOCAL=0        Disable the on-machine Tier-0 guard (route everything to the server)
  SHOMRA_GUARD_IGNORE=<globs> Comma-separated file globs the runtime guard treats as known-safe (never
                             withheld) - plus any .shomraignore in the working dir. For files with
                             benign patterns in source (detection code, fixtures, docs).
  SHOMRA_GUARD_ALWAYS_ESCALATE=1  Send every call to the server (full telemetry, higher overhead)
  SHOMRA_GUARD_TIMEOUT_MS=2000    Per-call server timeout budget (default 2000)
  SHOMRA_GUARD_BREAKER_MS=30000   Skip the server for this long after a failure (0 disables)
  SHOMRA_LLM_PROXY_BASE       Proxy base URL install-hook writes for Aider (default http://127.0.0.1:4141/openai/v1)
  SHOMRA_MODEL_GUARD=0        Disable the model-load screen in the PreToolUse hook
  SHOMRA_MODEL_CACHE=0        Disable the on-machine model-index verdict cache
  SHOMRA_MODEL_CACHE_TTL_MS   Model-cache freshness window (default 7 days)
`;

export const HELP_SECTIONS = [
  BANNER,
  USAGE,
  MODES,
  COMMANDS,
  GATE,
  CHECK,
  BASELINE_AND_SUPPRESSION,
  POLICY_AS_CODE,
  FIX,
  WHY,
  INSTALL_PRECOMMIT,
  MODEL_SCAN,
  MEMORY_SCAN,
  REDTEAM,
  HARDEN,
  AGENT_IDENTITY,
  LLM_PROXY,
  RUNTIME_FIREWALL,
  EXIT_CODES,
  ENV,
];
