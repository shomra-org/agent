#!/usr/bin/env node
/**
 * Shomra agent — the developer-machine plugin for the Shomra AI Security
 * Posture Management platform. Discovers the AI tooling on this machine
 * (MCP servers, AI rules files, AI tools, model keys), and reports it to your
 * Shomra org for analysis. Zero dependencies — Node built-ins only.
 *
 *   shomra init --key shm_live_… --url <your backend>   # connect to a Shomra org (optional)
 *   shomra scan            # discover + analyze, print a local report
 *   shomra report          # discover + send to the platform (alias: scan --report)
 *   shomra status          # show config + enrollment
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execSync } from 'node:child_process';
import { discoverAll } from './discovery.mjs';
import { localScan, localGate, grade, downrankCodeContext, SECRET_PATTERNS } from './guard-signals.mjs';
import { scanSourceFile, isScannableSource, isModelConfig } from './code-sast.mjs';
import { scanModelRefs, isModelRefScannable } from './model-refs.mjs';

const VERSION = '0.2.0';
const CONFIG_DIR = path.join(os.homedir(), '.shomra');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

// ── tiny ANSI helpers ────────────────────────────────────────────
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const dim = c('2'), bold = c('1'), red = c('31'), green = c('32'), yellow = c('33'), cyan = c('36'), magenta = c('35'), gray = c('90');
const SEV_COLOR = { CRITICAL: red, HIGH: red, MEDIUM: yellow, LOW: cyan, INFO: gray };
const VERDICT_COLOR = { FAIL: red, REVIEW: yellow, PASS: green };

function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch {
    return {};
  }
}
function saveConfig(cfg) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
}
function getMachineId(cfg) {
  if (cfg.machineId) return cfg.machineId;
  cfg.machineId = crypto.randomUUID();
  saveConfig(cfg);
  return cfg.machineId;
}
function resolveSettings(cfg) {
  // Local-first: there is NO built-in backend URL. Shomra runs fully on-machine
  // and only reaches a backend when the user has configured one — via
  // SHOMRA_URL, or `shomra init --url <your backend>` (persisted to config).
  // Absent that, `url` is null and every backend-only feature degrades cleanly
  // to the on-machine result. (Pin "localhost" → 127.0.0.1: it resolves to ::1
  // first under Node's fetch, but a backend may only answer on IPv4.)
  const raw = process.env.SHOMRA_URL || cfg.url || '';
  return {
    apiKey: process.env.SHOMRA_API_KEY || cfg.apiKey,
    url: raw ? raw.replace(/\/$/, '').replace('://localhost', '://127.0.0.1') : null,
  };
}

// ── guard latency budget + circuit breaker ───────────────────────
// The PreToolUse/PostToolUse guards run on EVERY tool call in a fresh process,
// so they must be snappy and self-healing when the backend is slow or down.
//   - A tight, configurable timeout caps the per-call wait (default 2s).
//   - A file-based breaker remembers a recent failure across processes: once
//     the backend times out/errors, the next calls fail-open INSTANTLY for a
//     cooldown window instead of each independently paying the full timeout.
// In strict mode the breaker is ignored — a fail-closed operator accepts the
// latency in exchange for enforcement even while the backend is unreachable.
const BREAKER_FILE = path.join(CONFIG_DIR, 'guard-breaker.json');
function clampInt(v, def, min, max) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : def;
}
function guardTimeoutMs() {
  return clampInt(process.env.SHOMRA_GUARD_TIMEOUT_MS, 2000, 200, 30000);
}
function breakerCooldownMs() {
  return clampInt(process.env.SHOMRA_GUARD_BREAKER_MS, 30000, 0, 600000);
}
function breakerOpen() {
  const cooldown = breakerCooldownMs();
  if (cooldown === 0) return false; // breaker disabled
  try {
    const { at } = JSON.parse(fs.readFileSync(BREAKER_FILE, 'utf8'));
    return typeof at === 'number' && Date.now() - at < cooldown;
  } catch {
    return false;
  }
}
function breakerTrip() {
  try {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
    fs.writeFileSync(BREAKER_FILE, JSON.stringify({ at: Date.now() }));
  } catch {
    /* best-effort — a missing breaker just means the next call retries */
  }
}
function breakerReset() {
  try {
    fs.rmSync(BREAKER_FILE, { force: true });
  } catch {
    /* ignore */
  }
}
// Machine identity attached to gate / guard / proxy calls so the backend can
// attribute the activity to this enrolled machine. Unlike machineInfo() it does
// NOT generate/persist a machineId — an unenrolled machine simply reports none,
// leaving the event unattributed rather than writing config from a hook.
function gateMachine() {
  let machineId;
  try {
    machineId = loadConfig().machineId;
  } catch {
    /* no config — unenrolled */
  }
  return { ...(machineId ? { machineId } : {}), hostname: os.hostname(), username: os.userInfo().username };
}
function machineInfo(cfg) {
  return {
    machineId: getMachineId(cfg),
    hostname: os.hostname(),
    platform: process.platform,
    osRelease: os.release(),
    username: os.userInfo().username,
    agentVersion: VERSION,
  };
}

async function api(url, key, route, body, opts = {}) {
  // No backend configured → make the reason explicit (callers catch this and
  // fall back to the on-machine result rather than surfacing a fetch error).
  if (!url) throw new Error('no backend configured — set SHOMRA_URL or run `shomra init --url <your backend>`');
  // Every backend call is bounded — an unreachable or hung backend must never
  // hang the CLI (which would freeze a dev's terminal or wedge a CI job).
  const timeoutMs = opts.timeoutMs ?? clampInt(process.env.SHOMRA_API_TIMEOUT_MS, 30000, 1000, 600000);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(`${url}${route}`, {
      method: 'POST',
      // Connection: close avoids undici keep-alive sockets lingering after the
      // command finishes (which can crash process.exit on Windows).
      headers: { 'Content-Type': 'application/json', 'X-Shomra-Key': key, Connection: 'close' },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
  } catch (e) {
    if (e?.name === 'AbortError') throw new Error(`request timed out after ${timeoutMs}ms (raise SHOMRA_API_TIMEOUT_MS or check the backend)`);
    throw e;
  } finally {
    clearTimeout(timer);
  }
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text };
  }
  if (!res.ok) {
    const msg = json?.message || json?.raw || res.statusText;
    throw new Error(`${res.status} ${Array.isArray(msg) ? msg.join(', ') : msg}`);
  }
  return json;
}

function parseFlags(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const body = a.slice(2);
      // Support both `--key value` and `--key=value`.
      const eq = body.indexOf('=');
      if (eq !== -1) {
        flags[body.slice(0, eq)] = body.slice(eq + 1);
        continue;
      }
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        flags[body] = next;
        i++;
      } else flags[body] = true;
    } else positional.push(a);
  }
  return { flags, positional };
}

// ── commands ─────────────────────────────────────────────────────
async function cmdInit(flags) {
  const cfg = loadConfig();
  const key = flags.key || process.env.SHOMRA_API_KEY;
  // No default backend (local-first): enrolling means pointing at a real Shomra
  // org, so the URL is required when one isn't already saved.
  const url = (flags.url || cfg.url || '').replace(/\/$/, '');
  if (!key) {
    console.error(red('✗') + ' Missing API key. Run: ' + bold('shomra init --key shm_live_… --url <your backend>'));
    process.exit(1);
  }
  if (!url) {
    console.error(red('✗') + ' Missing backend URL. Run: ' + bold('shomra init --key shm_live_… --url <your backend>'));
    process.exit(1);
  }
  cfg.apiKey = key;
  cfg.url = url;
  getMachineId(cfg);
  saveConfig(cfg);
  process.stdout.write(dim('Enrolling this machine… '));
  try {
    const res = await api(url, key, '/agent/enroll', { machine: machineInfo(cfg) });
    console.log(green('done'));
    console.log(`  ${green('✓')} Enrolled ${bold(os.hostname())} into org ${bold(res.org?.name ?? '?')}`);
    console.log(`  ${dim('Config saved to ' + CONFIG_FILE)}`);
    console.log(`\n  Next: ${bold('shomra report')} to send your first inventory.`);
  } catch (e) {
    console.log(red('failed'));
    console.error(`  ${red('✗')} ${e.message}`);
    process.exit(1);
  }
}

function discover(flags) {
  // With --path, scan exactly that tree. Without it, auto-expand to the
  // developer's real workspace (cwd + common project dirs under $HOME).
  const roots = flags.path ? [path.resolve(String(flags.path))] : [process.cwd()];
  return discoverAll(roots, { autoExpand: !flags.path });
}

function printAssets(assets) {
  const byType = {};
  for (const a of assets) byType[a.type] = (byType[a.type] ?? 0) + 1;
  console.log(bold('\n  Discovered AI assets'));
  console.log(
    '  ' +
      Object.entries(byType)
        .map(([t, n]) => `${cyan(n)} ${dim(t.replace('_', ' ').toLowerCase())}`)
        .join(dim('  ·  ')),
  );
  for (const a of assets) {
    console.log(`  ${gray('•')} ${bold(a.name)} ${dim(a.type)} ${a.vendor ? gray('(' + a.vendor + ')') : ''}`);
    if (a.identifier && a.identifier !== a.name) console.log(`      ${dim(a.identifier)}`);
  }
}

async function cmdScan(flags) {
  const cfg = loadConfig();
  const assets = discover(flags);
  if (flags.json && !flags.report) {
    console.log(JSON.stringify({ machine: machineInfo(cfg), assets }, null, 2));
    return;
  }
  console.log(bold(cyan('\n  Shomra')) + dim(` agent v${VERSION} — local scan`));
  printAssets(assets);

  if (flags.report) {
    await sendReport(cfg, assets, flags);
  } else {
    console.log(
      dim('\n  Run ') + bold('shomra report') + dim(' to analyze these on the platform and see findings.\n'),
    );
  }
}

async function sendReport(cfg, assets, flags) {
  const { apiKey, url } = resolveSettings(cfg);
  if (!apiKey) {
    console.error('\n' + red('✗') + ' Not configured. Run ' + bold('shomra init --key shm_live_…') + ' first.');
    process.exit(1);
  }
  process.stdout.write(dim('\n  Reporting to platform… '));
  try {
    const res = await api(url, apiKey, '/agent/report', { machine: machineInfo(cfg), assets });
    console.log(green('done') + dim(` (${res.assets} assets analyzed)`));
    if (flags.json) {
      console.log(JSON.stringify(res, null, 2));
      return;
    }
    console.log('');
    if (Array.isArray(res.results)) {
      for (const r of res.results.filter((x) => x.findingCount > 0)) {
        const vc = VERDICT_COLOR[r.verdict] || gray;
        console.log(`  ${vc('●')} ${bold(r.name)} ${dim('risk ' + r.riskScore)} ${vc(r.verdict)}`);
        for (const f of r.findings || []) {
          console.log(`      ${SEV_COLOR[f.severity](f.severity.padEnd(8))} ${f.title}`);
        }
      }
    }
    const crit = res.critical ?? 0;
    const high = res.high ?? 0;
    console.log(
      '\n  ' +
        (crit + high > 0
          ? `${red(crit + ' critical')} · ${yellow(high + ' high')} ${dim('— view & remediate at the Shomra dashboard')}`
          : green('No high-severity findings. ') + dim('Nice and clean.')),
    );
    console.log(dim(`  Endpoint: ${res.endpointId}\n`));
    if (crit > 0) process.exitCode = 2;
  } catch (e) {
    console.log(red('failed'));
    console.error(`  ${red('✗')} ${e.message}\n`);
    process.exit(1);
  }
}

// Human name for a key scope, inferred from its prefix. Accepts the current
// `shm_` prefix and the legacy pre-rebrand `dgx_` (older keys keep working).
function keyScope(key) {
  if (!key) return null;
  if (/^(shm|dgx)_gw_/.test(key)) return 'gateway';
  if (/^(shm|dgx)_ci_/.test(key)) return 'CI';
  return 'agent';
}

function cmdStatus() {
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  const enrolled = !!apiKey;
  console.log(bold(cyan('\n  Shomra agent')) + dim(` v${VERSION}`));

  // Mode banner — the whole point: what works right now, and what a key adds.
  if (enrolled) {
    console.log(`  ${dim('Mode     ')} ${green('● Enrolled')} ${dim(`(${keyScope(apiKey)} key)`)} — org policy, platform AI & dashboard telemetry active`);
  } else {
    console.log(`  ${dim('Mode     ')} ${cyan('● Local')} ${dim('— on-machine analysis only; nothing leaves this machine')}`);
    console.log(`  ${dim('         ')} ${dim('Run')} ${bold('shomra init --key shm_…')} ${dim('to add org policy, AI fixes, deep scans & the dashboard.')}`);
  }
  console.log(`  ${dim('Backend  ')} ${url}`);
  console.log(`  ${dim('API key  ')} ${apiKey ? green(apiKey.slice(0, 14) + '…') : dim('none (local mode)')}`);
  console.log(`  ${dim('Machine  ')} ${os.hostname()} ${dim('(' + (cfg.machineId || 'unenrolled') + ')')}`);
  console.log(`  ${dim('Config   ')} ${CONFIG_FILE}`);

  // What each tier unlocks, so the free/paid line is explicit.
  console.log(bold('\n  Available now') + dim(enrolled ? '' : ' (local, no key)'));
  console.log(`  ${green('✓')} ${dim('check · gate · doctor · protect · secrets · models · new · mcp add · why (offline)')}`);
  console.log(`  ${enrolled ? green('✓') : gray('○')} ${(enrolled ? dim : gray)('fix (AI) · deep scans (scan-zip/model-scan/memory-scan) · org policy · dashboard telemetry')}`);

  // Runtime firewall health — is the guard wired in, and is it in a state that
  // could freeze the agent? (checks Claude Code's global + project settings).
  const hookFiles = [
    path.join(os.homedir(), '.claude', 'settings.json'),
    path.join(process.cwd(), '.claude', 'settings.json'),
  ].filter((f) => {
    try {
      return fs.readFileSync(f, 'utf8').includes('shomra tool-guard');
    } catch {
      return false;
    }
  });
  const localOff = process.env.SHOMRA_GUARD_LOCAL === '0' || String(process.env.SHOMRA_GUARD_LOCAL).toLowerCase() === 'false';
  const strict = envFlag('SHOMRA_GUARD_STRICT');
  console.log(bold('\n  Runtime firewall'));
  console.log(`  ${dim('Hook     ')} ${hookFiles.length ? green('installed') + dim(' → ' + hookFiles.join(', ')) : yellow('not installed') + dim('  (run: shomra install-hook)')}`);
  console.log(`  ${dim('Tier 0   ')} ${localOff ? yellow('off') + dim(' (server-only)') : green('on') + dim(' — dangerous calls blocked on-machine, zero network')}`);
  console.log(`  ${dim('Mode     ')} ${strict ? 'fail-closed (strict)' : 'fail-open'}${dim(` · server timeout ${guardTimeoutMs()}ms · breaker ${breakerCooldownMs()}ms`)}`);
  console.log(`  ${dim('Breaker  ')} ${breakerOpen() ? red('OPEN') + dim(' — backend recently unreachable; server tier is being skipped') : green('closed')}\n`);
}

// ── the Dev Gate: vet an AI artifact BEFORE installing it ────────
//
//   shomra gate .mcp.json                       # auto-classified from the path
//   shomra gate my-skill/SKILL.md --kind skill
//   cat cfg.json | shomra gate --stdin --kind mcp --name github-server
//
// Exit codes: 0 = ALLOW (or FLAG), 1 = BLOCK, 2 = FLAG with --strict.
// Wire it as a pre-install / pre-commit hook so risky MCP servers, skills,
// slash commands and hooks never land on the machine unvetted.

const GATE_KINDS = ['mcp', 'skill', 'command', 'subagent', 'hook', 'rules', 'agent-card', 'memory', 'auto'];

// Detect the execution environment so the platform can split local-dev gate
// checks from CI/pipeline ones (and attribute repo/branch/commit for CISOs).
function detectEnv() {
  const e = process.env;
  const pick = (...keys) => {
    for (const k of keys) if (e[k]?.trim()) return e[k].trim();
    return undefined;
  };
  let ci = null;
  if (e.GITHUB_ACTIONS) ci = { ciProvider: 'github-actions', repo: e.GITHUB_REPOSITORY, ref: e.GITHUB_REF_NAME, commit: e.GITHUB_SHA };
  else if (e.GITLAB_CI) ci = { ciProvider: 'gitlab-ci', repo: e.CI_PROJECT_PATH, ref: e.CI_COMMIT_REF_NAME, commit: e.CI_COMMIT_SHA };
  else if (e.CIRCLECI) ci = { ciProvider: 'circleci', repo: e.CIRCLE_PROJECT_REPONAME, ref: e.CIRCLE_BRANCH, commit: e.CIRCLE_SHA1 };
  else if (e.TF_BUILD) ci = { ciProvider: 'azure-pipelines', repo: e.BUILD_REPOSITORY_NAME, ref: e.BUILD_SOURCEBRANCHNAME, commit: e.BUILD_SOURCEVERSION };
  else if (e.BITBUCKET_BUILD_NUMBER) ci = { ciProvider: 'bitbucket-pipelines', repo: e.BITBUCKET_REPO_FULL_NAME, ref: e.BITBUCKET_BRANCH, commit: e.BITBUCKET_COMMIT };
  else if (e.JENKINS_URL) ci = { ciProvider: 'jenkins', repo: pick('JOB_NAME'), ref: e.GIT_BRANCH, commit: e.GIT_COMMIT };
  else if (e.CI) ci = { ciProvider: 'ci', repo: undefined, ref: undefined, commit: undefined };

  if (ci) {
    const git = gitContext();
    return {
      environment: 'CI',
      ciProvider: ci.ciProvider,
      repo: ci.repo ?? git.repo,
      ref: ci.ref ?? git.ref,
      commit: ci.commit ?? git.commit,
    };
  }
  // Local dev — enrich with git if we're inside a repo.
  return { environment: 'LOCAL', ...gitContext() };
}

// Best-effort git context via the git CLI (zero extra deps). Never throws.
function gitContext() {
  const run = (args) => {
    try {
      return execSync(`git ${args}`, { stdio: ['ignore', 'pipe', 'ignore'], timeout: 2000 })
        .toString()
        .trim();
    } catch {
      return undefined;
    }
  };
  const origin = run('config --get remote.origin.url');
  let repo;
  if (origin) {
    const m = origin.match(/[:/]([^/:]+\/[^/]+?)(?:\.git)?$/);
    repo = m ? m[1] : undefined;
  }
  return { repo, ref: run('rev-parse --abbrev-ref HEAD'), commit: run('rev-parse HEAD') };
}

// Shape a localGate() result into the same object the backend /gate/check
// returns, so the printer/exit logic treats local and server results uniformly.
function localAsGateResult(local, name, kind) {
  return {
    decision: local.verdict,
    name: name || 'artifact',
    kind: kind || 'auto',
    riskScore: local.riskScore,
    findingCount: local.findings.length,
    findings: local.findings.map((f) => ({ severity: f.severity, title: f.title, remediationText: f.remediationText, ...(f.line ? { line: f.line } : {}) })),
  };
}

function printGateResult(res, source, flags) {
  if (flags.json) {
    console.log(JSON.stringify({ source, ...res }, null, 2));
    return;
  }
  const dc = res.decision === 'BLOCK' ? red : res.decision === 'FLAG' ? yellow : green;
  console.log(dc(res.decision) + (source === 'local' ? dim('  (on-machine)') : ''));
  console.log(`\n  ${dc('●')} ${bold(res.name)} ${dim(`${res.kind} · risk ${res.riskScore}/100 · ${res.findingCount ?? (res.findings || []).length} finding(s)`)}`);
  for (const f of res.findings || []) {
    console.log(`     ${SEV_COLOR[f.severity](String(f.severity).padEnd(8))} ${f.title}`);
    if (f.remediationText) console.log(`     ${dim('fix: ' + f.remediationText)}`);
  }
  for (const c of res.catalog || []) {
    const vc = VERDICT_COLOR[c.verdict] || gray;
    console.log(`     ${dim('catalog:')} ${c.name} ${vc(c.verdict ?? 'UNSCANNED')} ${dim('risk ' + c.riskScore)}`);
  }
  for (const p of res.policyHits || []) {
    // A policy hit the org triaged away (accepted-risk / ignored) is recorded but
    // did not drive the decision — show it struck-through-in-words so it's clear WHY
    // a CRITICAL didn't block.
    const note = p.suppressed ? dim('  (not enforced — accepted risk / ignored in your org)') : '';
    console.log(`     ${dim('policy:')} ${p.policy} ${dim('→')} ${p.action}${note}`);
  }
  const triaged = (res.policyHits || []).filter((p) => p.suppressed).length;
  if (triaged) console.log(`     ${dim(`${triaged} policy hit(s) suppressed by triage — reopen or let the acceptance expire to re-enforce.`)}`);
  const orgNote = source === 'local' ? dim(' (on-machine analysis; org policy not applied)') : '';
  if (res.decision === 'BLOCK') console.log(`\n  ${red('✗ Blocked.')}${orgNote} ${dim('Review the findings above.')}\n`);
  else if (res.decision === 'FLAG') console.log(`\n  ${yellow('⚠ Flagged.')}${orgNote} ${dim('Proceed with caution.')}\n`);
  else console.log(`\n  ${green('✓ Allowed.')}${orgNote} ${dim('No high-risk findings.')}\n`);
}

async function cmdGate(flags, positional) {
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);

  // Batch mode: gate every AI artifact under a directory (the CI story).
  if (flags.all) {
    return cmdGateAll(flags, positional, { apiKey, url });
  }

  const file = positional[0];
  let content;
  let relPath;
  let fullTarget = null;
  if (flags.stdin) {
    content = fs.readFileSync(0, 'utf8');
    relPath = flags.path || null;
  } else {
    if (!file) {
      console.error(red('✗') + ' Usage: ' + bold('shomra gate <file> [--kind mcp|skill|command|subagent|hook|rules|agent-card|memory] [--name x] [--strict] [--json]'));
      process.exit(1);
    }
    let target = path.resolve(String(file));
    // A directory gates its SKILL.md (the skill-install case).
    if (fs.existsSync(target) && fs.statSync(target).isDirectory()) {
      const skillMd = path.join(target, 'SKILL.md');
      if (!fs.existsSync(skillMd)) {
        console.error(red('✗') + ` ${file} is a directory with no SKILL.md — point at a file instead.`);
        process.exit(1);
      }
      target = skillMd;
    }
    if (!fs.existsSync(target)) {
      console.error(red('✗') + ` File not found: ${file}`);
      process.exit(1);
    }
    content = fs.readFileSync(target, 'utf8');
    relPath = path.relative(process.cwd(), target).split(path.sep).join('/');
    fullTarget = target;
  }

  const kind = flags.kind && GATE_KINDS.includes(String(flags.kind)) ? String(flags.kind) : undefined;
  const name = flags.name ? String(flags.name) : (relPath ? relPath.split('/').pop() : 'artifact');

  // ── Local analysis ALWAYS runs — a real verdict with no backend needed ──
  const local = localGate(content, { kind, path: relPath });

  // ── Enrich with the backend (org policy + governance) when reachable ──
  let res = null;
  let source = 'local';
  if (apiKey) {
    if (!flags.json) process.stdout.write(dim('  Checking with Shomra gate… '));
    try {
      res = await api(url, apiKey, '/gate/check', {
        ...(kind ? { kind } : {}),
        ...(flags.name ? { name: String(flags.name) } : {}),
        ...(relPath ? { path: relPath } : {}),
        content,
        machine: gateMachine(),
        env: detectEnv(),
        ...(flags.project ? { projectId: String(flags.project) } : {}),
      });
      source = 'server';
      if (!flags.json) console.log('');
    } catch (e) {
      if (!flags.json) {
        console.log(yellow('backend unavailable'));
        console.error(`  ${yellow('⚠')} ${e.message} ${dim('— falling back to on-machine analysis')}`);
      }
      // --strict = fail-closed: an outage fails the build, because org policy
      // could not be confirmed. Still show what the local analysis found.
      if (flags.strict) {
        printGateResult(localAsGateResult(local, name, kind), 'local', flags);
        if (!flags.json) console.log(`  ${red('✗ Failing closed (--strict): backend unreachable, org policy unverified.')}\n`);
        process.exitCode = 1;
        return;
      }
    }
  } else if (!flags.json) {
    console.error(`  ${dim('Not enrolled — on-machine analysis only. Run')} ${bold('shomra init')} ${dim('to also apply org policy.')}`);
  }

  const base = res || localAsGateResult(local, name, kind);
  // Fold in on-machine SAST: the artifact itself if it is a source file / model
  // config, plus a skill's bundled scripts (the backend only saw one file).
  const final = mergeSastIntoResult(base, collectLocalSast({ fullPath: fullTarget, relPath, kind, content }));
  printGateResult(final, source, flags);

  if (final.decision === 'BLOCK') process.exitCode = 1;
  else if (final.decision === 'FLAG' && flags.strict) process.exitCode = 2;
}

// ── LLM Guard proxy: guardrail every LLM call from this machine ──
//
//   shomra llm-proxy [--port 4141] [--project <projectId>]
//
// Starts a local proxy that forwards OpenAI/Anthropic SDK traffic through the
// Shomra backend, where every prompt and completion is screened against org
// policy. Point your SDK at it with an env var — zero code changes:
//
//   OPENAI_BASE_URL    = http://127.0.0.1:4141/openai/v1
//   ANTHROPIC_BASE_URL = http://127.0.0.1:4141/anthropic
//
// Blocked calls come back as a provider-shaped HTTP 403, so SDKs raise a
// normal API error with the block reason. Keep your real provider key in the
// usual env var (the SDK sends it; Shomra passes it through) — or set the org
// key on the backend and use your shm_ key as the provider key.
//
// Providers mirror the backend registry (UPSTREAM in llm-proxy.service.ts):
// openai + every OpenAI-compatible API (groq/mistral/xai/deepseek/openrouter/
// together) speak the OpenAI wire format; anthropic and gemini have their own.

const LLM_PROVIDERS = ['openai', 'anthropic', 'gemini', 'groq', 'mistral', 'xai', 'deepseek', 'openrouter', 'together'];

async function cmdLlmProxy(flags) {
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  if (!apiKey) {
    console.error('\n' + red('✗') + ' Not configured. Run ' + bold('shomra init --key shm_live_…') + ' first.');
    process.exit(1);
  }
  const port = parseInt(flags.port, 10) || 4141;
  const project = flags.project ? String(flags.project) : null;
  const agentId = resolveAgentIdentityHandle(flags);
  const actor = `${os.hostname()}/${os.userInfo().username}`;
  // One correlation id per proxy run — the platform groups this session's
  // inspections together. Callers can override per request with their own
  // x-shomra-session header.
  const sessionId = `proxy-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const { createServer } = await import('node:http');

  const providerRe = new RegExp(`^/(${LLM_PROVIDERS.join('|')})(/.*)?$`);
  const server = createServer(async (req, res) => {
    const m = String(req.url).match(providerRe);
    if (!m) {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: { message: `Unknown route — use /<provider>/… (providers: ${LLM_PROVIDERS.join(', ')})` } }));
      return;
    }
    const route = `/llm/${m[1]}${m[2] ?? '/'}`;
    const chunks = [];
    for await (const ch of req) chunks.push(ch);

    const headers = { ...req.headers };
    delete headers.host;
    delete headers.connection;
    delete headers['content-length'];
    delete headers['accept-encoding']; // let fetch negotiate + transparently decompress
    delete headers.expect; // undici rejects "Expect: 100-continue" (some HTTP clients add it)
    headers['x-shomra-key'] = apiKey;
    headers['x-shomra-actor'] = actor;
    if (cfg.machineId) headers['x-shomra-machine'] = cfg.machineId;
    headers['x-shomra-source'] = 'shomra llm-proxy';
    if (!headers['x-shomra-session']) headers['x-shomra-session'] = sessionId;
    if (project) headers['x-shomra-project'] = project;
    // Present the non-human agent identity so the guard authorizes THIS agent
    // (unless the caller already set its own per-request x-shomra-agent).
    if (agentId && !headers['x-shomra-agent']) headers['x-shomra-agent'] = agentId;

    let up;
    try {
      up = await fetch(`${url}${route}`, {
        method: req.method,
        headers,
        body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks),
      });
    } catch (e) {
      const cause = e.cause ? ` (${e.cause.code ?? ''} ${e.cause.message ?? e.cause})` : '';
      res.writeHead(502, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: { message: `Shomra backend unreachable at ${url}: ${e.message}${cause}` } }));
      console.log(`  ${red('✗')} ${req.method} ${req.url} ${red('backend unreachable')}${dim(cause)} ${dim('hdrs: ' + Object.keys(headers).join(','))}`);
      return;
    }

    const outHeaders = {};
    for (const [k, v] of up.headers) {
      if (!['content-length', 'transfer-encoding', 'content-encoding', 'connection'].includes(k)) outHeaders[k] = v;
    }
    res.writeHead(up.status, outHeaders);
    try {
      if (up.body) for await (const chunk of up.body) res.write(chunk);
    } catch { /* client hung up mid-stream */ }
    res.end();

    const mark = up.status === 403 ? red('BLOCKED') : up.status >= 400 ? yellow(String(up.status)) : green(String(up.status));
    console.log(`  ${dim(new Date().toTimeString().slice(0, 8))} ${bold(m[1].padEnd(10))} ${dim(req.method)} ${m[2] ?? '/'} ${mark}`);
  });

  server.listen(port, '127.0.0.1', () => {
    console.log(bold(cyan('\n  Shomra LLM Guard')) + dim(` — local proxy v${VERSION}`));
    console.log(`  ${green('●')} Listening on ${bold(`http://127.0.0.1:${port}`)} ${dim('→ ' + url + ' → provider')}`);
    if (project) console.log(`  ${dim('Project  ')} ${project}`);
    console.log(`  ${dim('Actor    ')} ${actor}\n`);
    console.log(bold('  Route your SDKs through the guard (no code changes):'));
    console.log(dim('    OpenAI / Anthropic (PowerShell)'));
    console.log(`      $env:OPENAI_BASE_URL    = "http://127.0.0.1:${port}/openai/v1"`);
    console.log(`      $env:ANTHROPIC_BASE_URL = "http://127.0.0.1:${port}/anthropic"`);
    console.log(dim('    OpenAI / Anthropic (bash/zsh)'));
    console.log(`      export OPENAI_BASE_URL=http://127.0.0.1:${port}/openai/v1`);
    console.log(`      export ANTHROPIC_BASE_URL=http://127.0.0.1:${port}/anthropic`);
    console.log(dim('    Gemini — point the Google GenAI SDK base URL at'));
    console.log(`      http://127.0.0.1:${port}/gemini`);
    console.log(dim(`    OpenAI-compatible (${['groq', 'mistral', 'xai', 'deepseek', 'openrouter', 'together'].join(', ')}) — set the SDK baseURL to`));
    console.log(`      http://127.0.0.1:${port}/<provider>/v1`);
    console.log(dim('\n  Prompts and completions are screened against org policy;'));
    console.log(dim('  blocked calls return HTTP 403 with the reason. Ctrl+C to stop.\n'));
  });
}

// ── batch gate: vet every AI artifact in a repo/dir (the CI pre-merge story) ──
//
//   shomra gate --all [dir] [--strict] [--json] [--project <id>]
//
// Walks the tree for the AI-artifact surfaces an LLM can run (MCP configs,
// Skills, slash commands, subagents, hooks, rules files), gates each, and
// aggregates: exits 1 if ANY is BLOCKed (2 if any FLAG with --strict). Drop it
// in a CI job to fail the build when a risky artifact lands in the repo.

const ARTIFACT_MATCHERS = [
  { kind: 'mcp', re: /(^|\/)\.?mcp\.json$/i },
  { kind: 'mcp', re: /(^|\/)\.(vscode|cursor)\/mcp\.json$/i },
  { kind: 'skill', re: /(^|\/)SKILL\.md$/i },
  { kind: 'command', re: /(^|\/)\.claude\/commands\/[^/]+\.md$/i },
  { kind: 'subagent', re: /(^|\/)\.claude\/agents\/[^/]+\.md$/i },
  { kind: 'hook', re: /(^|\/)\.claude\/settings(\.local)?\.json$/i },
  { kind: 'agent-card', re: /(^|\/)\.well-known\/agent(-card)?\.json$/i },
  { kind: 'agent-card', re: /(^|\/)agent[-_]card\.json$/i },
  { kind: 'rules', re: /(^|\/)(CLAUDE|AGENTS|GEMINI|CONVENTIONS)\.md$/i },
  { kind: 'rules', re: /(^|\/)\.(cursorrules|windsurfrules|clinerules|aiderrules|continuerules|goosehints)$/i },
  { kind: 'rules', re: /(^|\/)\.github\/copilot-instructions\.md$/i },
  { kind: 'rules', re: /(^|\/)\.cursor\/rules\/[^/]+\.mdc$/i },
  { kind: 'memory', re: /(^|\/)MEMORY\.md$/i },
  { kind: 'memory', re: /(^|\/)(mem0|letta_memory|memgpt_memory)\.json$/i },
  { kind: 'memory', re: /(^|\/)(\.mem0|\.letta|\.memgpt|memory)\/[^/]+\.(md|json)$/i },
];
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'out', 'vendor', '.venv', '__pycache__']);
const MAX_ARTIFACT_BYTES = 1_000_000;

function walkArtifacts(root) {
  const found = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (!SKIP_DIRS.has(ent.name)) stack.push(full);
        continue;
      }
      const rel = path.relative(root, full).split(path.sep).join('/');
      const match = ARTIFACT_MATCHERS.find((m) => m.re.test(rel));
      if (match) found.push({ full, rel, kind: match.kind });
    }
  }
  return found;
}

// ── local SAST integration ──────────────────────────────────────────
// The gate's flat/structural checks catch payloads embedded in the artifact
// text; this catches the code-level RCE shapes a skill's shipped .py/.js helper
// (or a model config.json) carries — eval/exec/pickle/child_process/decode-and-
// run/trust_remote_code/auto_map — which the platform's workspace + model scans
// catch server-side. Runs the SAME rule engine ON-MACHINE (agent/code-sast.mjs).
const MAX_SAST_FILES = 60;

// Bounded walk of a skill's directory for the source files it bundles + executes.
function walkScripts(root) {
  const found = [];
  const stack = [root];
  while (stack.length && found.length < MAX_SAST_FILES) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) { if (!SKIP_DIRS.has(ent.name)) stack.push(full); continue; }
      if (isScannableSource(ent.name) || isModelConfig(ent.name)) {
        found.push({ full, rel: path.relative(process.cwd(), full).split(path.sep).join('/') });
        if (found.length >= MAX_SAST_FILES) break;
      }
    }
  }
  return found;
}

/** Map a SAST hit into a gate-finding, preserving the rich evidence (--json/IDE). */
function sastToFinding(h) {
  const base = h.file ? h.file.split('/').pop() : '';
  return {
    severity: h.severity,
    title: `Risky code — ${h.title}${base ? ` in ${base}` : ''} (${h.sink})`,
    remediationText: h.remediation,
    ...(h.line ? { line: h.line } : {}),
    analysis: 'sast', ruleId: h.ruleId, cwe: h.cwe, sink: h.sink, source: h.source,
    file: h.file, snippet: h.snippet, snippetStartLine: h.snippetStartLine,
  };
}

// Collect local SAST findings for one gated artifact: the artifact itself when
// it is a source file / model config (`gate server.js`), plus — for a skill —
// the scripts bundled in its directory (mirrors the platform's per-skill scan).
function collectLocalSast({ fullPath, relPath, kind, content }) {
  const out = [];
  if (relPath && (isScannableSource(relPath) || isModelConfig(relPath))) {
    for (const h of scanSourceFile(content || '', relPath)) out.push(sastToFinding(h));
  }
  const isSkill = kind === 'skill' || /(^|\/)SKILL\.md$/i.test(relPath || '');
  if (isSkill && fullPath) {
    for (const s of walkScripts(path.dirname(fullPath))) {
      let text;
      try { if (fs.statSync(s.full).size > MAX_ARTIFACT_BYTES) continue; text = fs.readFileSync(s.full, 'utf8'); } catch { continue; }
      for (const h of scanSourceFile(text, s.rel)) out.push(sastToFinding(h));
    }
  }
  return out;
}

const DEC_RANK = { ALLOW: 0, FLAG: 1, BLOCK: 2 };
/** Fold SAST findings into a gate result, escalating the decision to the worse of
 *  the two (rule-origin SAST is high-confidence; it never downgrades). */
function mergeSastIntoResult(result, sastFindings) {
  if (!sastFindings || !sastFindings.length) return result;
  const findings = [...(result.findings || []), ...sastFindings];
  const g = grade(findings);
  const decision = DEC_RANK[g.verdict] > DEC_RANK[result.decision] ? g.verdict : result.decision;
  return { ...result, decision, riskScore: Math.max(result.riskScore || 0, g.riskScore), findingCount: findings.length, findings };
}

// ── suppression: .shomraignore + inline // shomra-ignore + baseline ──────
// Devs need a friction-free escape hatch or a single false positive gets the
// tool deleted. Three layers, all re-grade the artifact so a fully-suppressed
// file drops to ALLOW and never fails the build:
//   • .shomraignore   — repo file: `glob` (skip file) or `glob :: title-substr`.
//   • inline comment  — `// shomra-ignore[: reason]` / `# shomra-ignore` on the
//                        finding's line or the one above; `shomra-ignore-file`
//                        anywhere in the first lines skips the whole file.
//   • baseline        — `.shomra/baseline.json` of accepted fingerprints
//                        (`shomra baseline`), so only NEW findings fail.
const IGNORE_MARK = /(?:\/\/|#|<!--|;)\s*shomra-ignore(-file|-next-line)?\b[:\s]?(.*)$/i;

function globToRe(glob) {
  const esc = String(glob).trim().replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, ' ').replace(/\*/g, '[^/]*').replace(/ /g, '.*').replace(/\?/g, '.');
  return new RegExp('^' + esc + '$', 'i');
}

// Parse .shomraignore into file-skip globs and per-finding (glob :: substr) rules.
function loadIgnoreRules(root) {
  const fileGlobs = [], findingRules = [];
  let raw;
  try { raw = fs.readFileSync(path.join(root, '.shomraignore'), 'utf8'); } catch { return { fileGlobs, findingRules }; }
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const sep = t.indexOf('::');
    if (sep !== -1) findingRules.push({ re: globToRe(t.slice(0, sep).trim()), titleSub: t.slice(sep + 2).trim().toLowerCase() });
    else fileGlobs.push(globToRe(t));
  }
  return { fileGlobs, findingRules };
}

function loadBaseline(root) {
  try { return new Set(JSON.parse(fs.readFileSync(path.join(root, '.shomra', 'baseline.json'), 'utf8')).fingerprints || []); } catch { return null; }
}
// Line-independent identity so a finding stays suppressed when code moves.
function findingFingerprint(relPath, f) {
  return crypto.createHash('sha1').update(`${relPath}::${f.ruleId || f.title}`).digest('hex').slice(0, 16);
}

// Inline-comment suppression for one finding, using a per-file line cache.
function inlineSuppressed(fullPath, line, cache) {
  if (!fullPath) return false;
  let lines = cache.get(fullPath);
  if (lines === undefined) {
    try { lines = fs.readFileSync(fullPath, 'utf8').split(/\r?\n/); } catch { lines = null; }
    cache.set(fullPath, lines);
  }
  if (!lines) return false;
  // Whole-file opt-out in the first 5 lines. `shomra-ignore-file` is accepted as
  // a bare token too (not just in a comment) so JSON/config files — which have no
  // comment syntax — can still opt out with a `"_shomra": "shomra-ignore-file"` key.
  for (let i = 0; i < Math.min(5, lines.length); i++) {
    if (/\bshomra-ignore-file\b/i.test(lines[i])) return true;
  }
  if (!line) return false;
  const onLine = IGNORE_MARK.exec(lines[line - 1] || '');
  if (onLine && (!onLine[1] || onLine[1].toLowerCase() !== '-file')) return true;
  const above = IGNORE_MARK.exec(lines[line - 2] || '');
  if (above && (!above[1] || above[1].toLowerCase() === '-next-line')) return true;
  return false;
}

// Why (if at all) a finding is suppressed: ignore-rule / inline / baseline.
function suppressionReason(r, f, rules, baseline, cache) {
  if (rules.fileGlobs.some((re) => re.test(r.path))) return 'ignored (.shomraignore)';
  const title = String(f.title || '').toLowerCase();
  if (rules.findingRules.some((rule) => rule.re.test(r.path) && title.includes(rule.titleSub))) return 'ignored (.shomraignore)';
  if (baseline && baseline.has(findingFingerprint(r.path, f))) return 'baseline';
  if (inlineSuppressed(r.full, f.line, cache)) return 'inline';
  return null;
}

// Apply suppression to a gate result, re-grading from the surviving findings.
function suppressResult(r, rules, baseline, cache) {
  const kept = [], suppressed = [];
  for (const f of r.findings || []) {
    const reason = suppressionReason(r, f, rules, baseline, cache);
    (reason ? suppressed : kept).push(reason ? { ...f, suppressedBy: reason } : f);
  }
  if (!suppressed.length) return r;
  const g = grade(kept);
  return { ...r, findings: kept, decision: g.verdict, riskScore: g.riskScore, findingCount: kept.length, suppressedFindings: suppressed, suppressedCount: suppressed.length };
}

// Suppress a whole results array and recompute the blocked/flagged/suppressed
// tallies. Central so check / gate --all / single gate behave identically.
function applySuppressions(results, root, { baseline } = {}) {
  const rules = loadIgnoreRules(root);
  const base = baseline ? loadBaseline(root) : null;
  const cache = new Map();
  let blocked = 0, flagged = 0, suppressed = 0;
  const out = results.map((r) => {
    const s = suppressResult(r, rules, base, cache);
    suppressed += s.suppressedCount || 0;
    if (s.decision === 'BLOCK') blocked++;
    else if (s.decision === 'FLAG') flagged++;
    return s;
  });
  return { results: out, blocked, flagged, suppressed };
}

// ── SARIF 2.1.0 output — native inline annotations in GitHub / GitLab PRs ──
const SARIF_LEVEL = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note', INFO: 'note' };
const SARIF_SEC = { CRITICAL: '9.0', HIGH: '7.5', MEDIUM: '5.0', LOW: '3.0', INFO: '1.0' };
function sarifRuleId(f) {
  return f.ruleId || 'shomra.' + String(f.title || 'finding').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60);
}
function toSarif(results) {
  const rules = new Map();
  const sarifResults = [];
  for (const r of results) {
    for (const f of r.findings || []) {
      const id = sarifRuleId(f);
      if (!rules.has(id)) rules.set(id, { id, name: id, shortDescription: { text: String(f.title || id).slice(0, 200) }, ...(f.cwe ? { properties: { cwe: f.cwe, tags: ['security', f.cwe] } } : { properties: { tags: ['security'] } }) });
      sarifResults.push({
        ruleId: id,
        level: SARIF_LEVEL[f.severity] || 'warning',
        message: { text: f.remediationText ? `${f.title} — ${f.remediationText}` : String(f.title || id) },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.file || r.path }, ...(f.line ? { region: { startLine: f.line } } : {}) } }],
        properties: { severity: f.severity, 'security-severity': SARIF_SEC[f.severity] || '5.0', ...(f.cwe ? { cwe: f.cwe } : {}) },
      });
    }
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'Shomra', informationUri: 'https://shomra.dev', version: VERSION, rules: [...rules.values()] } }, results: sarifResults }],
  };
}

// ── policy-as-code: .shomra/policy.yml — team gate rules, versioned in the repo ──
// Devs prefer config-in-repo over a dashboard. A committed policy lets a team set
// its own block/flag thresholds and allow-list, reviewed in PRs like any code.
//   block: high        # min severity that BLOCKS (critical|high|medium|low|none)
//   flag:  medium      # min severity that FLAGS
//   allow:             # finding-title substrings to always downgrade away
//     - "IPv4 address"
// Authority: for a LOCAL verdict the repo policy fully re-grades; when the backend
// returned an org decision, the repo policy can only make it STRICTER (worst-wins),
// never loosen org enforcement — mirroring the platform's policy hierarchy.
const SEV_THRESH = { none: 99, critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const SEV_RANK_LOCAL = { INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };
const WEIGHT_LOCAL = { INFO: 2, LOW: 8, MEDIUM: 20, HIGH: 40, CRITICAL: 70 };

function parseSimpleYaml(text) {
  const data = {}; let key = null;
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, '');
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const li = /^\s*-\s+(.*)$/.exec(line);
    if (li && key) { (Array.isArray(data[key]) ? data[key] : (data[key] = [])).push(unquote(li[1].trim())); continue; }
    const kv = /^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/.exec(line);
    if (!kv) continue;
    key = kv[1];
    const v = kv[2].trim();
    data[key] = v === '' ? (data[key] ?? null) : v.startsWith('[') ? v.replace(/^\[|\]$/g, '').split(',').map((s) => unquote(s.trim())).filter(Boolean) : unquote(v);
  }
  return data;
}
function unquote(s) { return String(s).replace(/^["']|["']$/g, ''); }

function loadRepoPolicy(root) {
  let text, file;
  for (const f of ['policy.yml', 'policy.yaml', 'policy.json']) {
    try { text = fs.readFileSync(path.join(root, '.shomra', f), 'utf8'); file = f; break; } catch { /* next */ }
  }
  if (text === undefined) return null;
  let raw;
  if (file.endsWith('.json')) { try { raw = JSON.parse(text); } catch { return null; } }
  else raw = parseSimpleYaml(text);
  return {
    block: SEV_THRESH[String(raw.block || '').toLowerCase()] ?? SEV_RANK_LOCAL.CRITICAL,
    flag: SEV_THRESH[String(raw.flag || '').toLowerCase()] ?? SEV_RANK_LOCAL.HIGH,
    allow: [].concat(raw.allow || []).map((s) => String(s).toLowerCase()),
  };
}

// Re-grade a result under a repo policy. Drops allow-listed findings, applies the
// team's block/flag thresholds; only tightens a server decision, fully sets a
// local one.
function applyRepoPolicy(r, policy) {
  if (!policy) return r;
  let findings = r.findings || [];
  let dropped = 0;
  if (policy.allow.length) {
    const keep = [];
    for (const f of findings) {
      if (policy.allow.some((sub) => sub && String(f.title || '').toLowerCase().includes(sub))) dropped++;
      else keep.push(f);
    }
    findings = keep;
  }
  let worst = 0;
  for (const f of findings) worst = Math.max(worst, SEV_RANK_LOCAL[f.severity] || 0);
  const pv = worst >= policy.block ? 'BLOCK' : worst >= policy.flag ? 'FLAG' : 'ALLOW';
  const riskScore = Math.min(100, findings.reduce((s, f) => s + (WEIGHT_LOCAL[f.severity] || 0), 0));
  // Server decision is authoritative — repo policy can only tighten it. A purely
  // local decision is fully replaced by the repo policy.
  const decision = r.source === 'server' ? (DEC_RANK[pv] > DEC_RANK[r.decision] ? pv : r.decision) : pv;
  const extra = dropped ? { suppressedCount: (r.suppressedCount || 0) + dropped, suppressedFindings: [...(r.suppressedFindings || []), ...(r.findings || []).filter((f) => !findings.includes(f)).map((f) => ({ ...f, suppressedBy: 'policy allow' }))] } : {};
  return { ...r, findings, findingCount: findings.length, decision, riskScore: r.source === 'server' ? Math.max(r.riskScore || 0, riskScore) : riskScore, ...extra };
}

// Gate a list of {full, rel, kind} artifacts: local analysis always runs, the
// backend enriches when reachable (and is skipped for the rest of the batch
// after one failure, so a CI job never eats one timeout per artifact). Prints
// one line per artifact unless --json. Shared by `gate --all` and `check`.
async function gateArtifactList(artifacts, { apiKey, url, env, flags, root }) {
  const results = [];
  const quiet = flags.json || flags.sarif; // machine-readable output → no progress chatter
  let blocked = 0;
  let flagged = 0;
  let suppressed = 0;
  let backendDown = false;
  // Suppression context (loaded once): .shomraignore + baseline + inline cache.
  const suppress = !flags['no-suppress'];
  const rules = suppress ? loadIgnoreRules(root || process.cwd()) : { fileGlobs: [], findingRules: [] };
  const baseline = suppress && !flags['no-baseline'] ? loadBaseline(root || process.cwd()) : null;
  const lineCache = new Map();
  // Team policy-as-code (.shomra/policy.yml) re-grades each result; --no-policy skips.
  const policy = flags['no-policy'] ? null : loadRepoPolicy(root || process.cwd());

  // ── Phase 1: read + LOCAL analysis (sync, cheap) for every artifact ──
  const prepared = [];
  for (const a of artifacts) {
    let content;
    try {
      if (fs.statSync(a.full).size > MAX_ARTIFACT_BYTES) {
        if (!quiet) console.log(`  ${gray('•')} ${dim(a.rel)} ${yellow('skipped (too large)')}`);
        continue;
      }
      content = fs.readFileSync(a.full, 'utf8');
    } catch { continue; }
    const local = localGate(content, { kind: a.kind, path: a.rel });
    const sast = collectLocalSast({ fullPath: a.full, relPath: a.rel, kind: a.kind, content });
    prepared.push({ a, content, local, sast });
  }

  // ── Phase 2: backend enrich, BOUNDED-PARALLEL (was one sequential round-trip
  //    per artifact). Order-preserving; on the first outage stop starting new
  //    calls (a down backend never costs N timeouts).
  const server = new Array(prepared.length).fill(null);
  if (apiKey) {
    const conc = clampInt(process.env.SHOMRA_GATE_CONCURRENCY, 8, 1, 32);
    let next = 0;
    const worker = async () => {
      while (true) {
        const i = next++;
        if (i >= prepared.length || backendDown) return;
        const { a, content } = prepared[i];
        try {
          server[i] = await api(url, apiKey, '/gate/check', {
            kind: a.kind, path: a.rel, content, machine: gateMachine(), env,
            ...(flags.project ? { projectId: String(flags.project) } : {}),
          });
        } catch (e) {
          if (!backendDown && !quiet) console.log(`  ${yellow('⚠')} ${dim('backend unavailable (' + e.message + ') — on-machine analysis for the rest')}`);
          backendDown = true;
          return;
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(conc, prepared.length) }, worker));
  }

  // ── Phase 3: assemble in order — fold SAST, suppress, apply policy, tally, print ──
  for (let i = 0; i < prepared.length; i++) {
    const { a, content, local, sast } = prepared[i];
    const res = server[i];
    const source = res ? 'server' : 'local';
    const merged = mergeSastIntoResult(res || localAsGateResult(local, a.rel, a.kind), sast);
    const r0 = { path: a.rel, full: a.full, kind: a.kind, source, ...merged };
    const rs = suppress ? suppressResult(r0, rules, baseline, lineCache) : r0;
    const r = applyRepoPolicy(rs, policy);
    suppressed += r.suppressedCount || 0;
    results.push(r);
    if (r.decision === 'BLOCK') blocked++;
    else if (r.decision === 'FLAG') flagged++;
    if (!quiet) {
      const dc = r.decision === 'BLOCK' ? red : r.decision === 'FLAG' ? yellow : green;
      const supNote = r.suppressedCount ? dim(` · ${r.suppressedCount} suppressed`) : '';
      console.log(`  ${dc('●')} ${bold(r.name)} ${dim(a.rel)}${source === 'local' ? dim(' ·local') : ''} ${dc(r.decision)} ${dim('risk ' + r.riskScore + ' · ' + (r.findingCount ?? (r.findings || []).length) + ' finding(s)')}${supNote}`);
      for (const f of (r.findings || []).slice(0, 3)) {
        console.log(`      ${SEV_COLOR[f.severity](String(f.severity).padEnd(8))} ${f.title}`);
      }
    }
  }
  return { results, blocked, flagged, suppressed, backendDown };
}

async function cmdGateAll(flags, positional, { apiKey, url }) {
  // `--all <dir>` sets flags.all to the dir; bare `--all` leaves it true → use positional or cwd.
  const dirArg = typeof flags.all === 'string' ? flags.all : positional[0] || '.';
  const root = path.resolve(dirArg);
  const env = detectEnv();
  const artifacts = walkArtifacts(root);

  if (!artifacts.length) {
    if (flags.json) console.log(JSON.stringify({ scanned: 0, results: [] }, null, 2));
    else console.log(dim(`\n  No AI artifacts found under ${root}. Nothing to gate.\n`));
    return;
  }

  if (!flags.json && !flags.sarif) console.log(bold(cyan('\n  Shomra gate')) + dim(` — batch (${artifacts.length} artifact${artifacts.length > 1 ? 's' : ''} · ${env.environment}${env.ciProvider ? ' · ' + env.ciProvider : ''})`));

  const { results, blocked, flagged, suppressed, backendDown } = await gateArtifactList(artifacts, { apiKey, url, env, flags, root });

  // --strict is fail-closed: if the backend was unreachable we can't confirm org
  // policy, so fail the build even if local analysis was clean.
  const strictOutage = backendDown && flags.strict;

  if (flags.sarif) {
    console.log(JSON.stringify(toSarif(results), null, 2));
    if (blocked > 0 || strictOutage) process.exitCode = 1;
    else if (flagged > 0 && flags.strict) process.exitCode = 2;
    return;
  }
  if (flags.json) {
    console.log(JSON.stringify({ scanned: results.length, blocked, flagged, suppressed, backendDown, environment: env.environment, results }, null, 2));
  } else {
    console.log(
      '\n  ' +
        (blocked > 0
          ? red(`✗ ${blocked} blocked`) + dim(` · ${flagged} flagged · ${results.length - blocked - flagged} allowed`)
          : flagged > 0
            ? yellow(`⚠ ${flagged} flagged`) + dim(` · ${results.length - flagged} allowed`)
            : green(`✓ All ${results.length} artifacts allowed.`)) +
        (suppressed ? dim(` · ${suppressed} suppressed`) : '') +
        (backendDown ? yellow('  (on-machine analysis — org policy not applied)') : dim(' — full activity in the Shomra dashboard → Gate Activity')) +
        '\n',
    );
    if (strictOutage) console.log(`  ${red('✗ Failing closed (--strict): backend unreachable, org policy unverified.')}\n`);
  }

  // Set exitCode (not process.exit) so pending sockets drain cleanly on Windows.
  if (blocked > 0 || strictOutage) process.exitCode = 1;
  else if (flagged > 0 && flags.strict) process.exitCode = 2;
}

// ── the one dev command: "is my repo safe?" ─────────────────────
//
//   shomra check                 # gate every AI artifact under the repo
//   shomra check --staged        # only git-STAGED artifacts (pre-commit / on-save)
//   shomra check --changed       # only artifacts changed vs HEAD
//   shomra check --fix           # remediate what's blocked/flagged, in place
//   shomra check --json          # machine-readable (what the IDE extension calls)
//
// Local-first like `gate`: real on-machine analysis always runs, so a verdict
// comes back with no backend and no key; enrolling layers org policy on top.
// Exit 0 = clean, 1 = blocked, 2 = flagged with --strict.
async function cmdCheck(flags, positional) {
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  const root = path.resolve(positional[0] || flags.path || '.');
  const env = detectEnv();

  let artifacts = walkArtifacts(root);
  // Scope to the changed/staged set when asked — the fast pre-commit / on-save loop.
  if (flags.staged || flags.changed) {
    const changed = gitChangedArtifacts(root, { staged: !!flags.staged });
    if (changed === null) {
      if (!flags.json) console.error(`  ${yellow('⚠')} ${dim('not a git repo (or git unavailable) — checking the whole tree')}`);
    } else {
      const set = new Set(changed);
      artifacts = artifacts.filter((a) => set.has(a.rel));
    }
  }

  if (!artifacts.length) {
    if (flags.json) console.log(JSON.stringify({ scanned: 0, blocked: 0, flagged: 0, results: [] }, null, 2));
    else console.log(green('\n  ✓ No AI artifacts to check') + dim((flags.staged || flags.changed) ? ' in the changed set.' : ` under ${root}.`) + '\n');
    return;
  }

  if (!flags.json && !flags.sarif) {
    const scope = flags.staged ? 'staged' : flags.changed ? 'changed' : env.environment;
    console.log(bold(cyan('\n  Shomra check')) + dim(` — ${artifacts.length} artifact${artifacts.length > 1 ? 's' : ''} · ${scope}${env.ciProvider ? ' · ' + env.ciProvider : ''}`));
    if (!apiKey) console.error(`  ${dim('On-machine analysis only — run')} ${bold('shomra init')} ${dim('to also apply org policy.')}`);
  }

  const { results, blocked, flagged, suppressed, backendDown } = await gateArtifactList(artifacts, { apiKey, url, env, flags, root });

  if (flags.sarif) {
    console.log(JSON.stringify(toSarif(results), null, 2));
    if (blocked) process.exitCode = 1;
    else if (flagged && flags.strict) process.exitCode = 2;
    return;
  }

  // --fix: remediate the artifacts that aren't clean, in place (each fix is
  // generated on the platform and written back to the local file).
  let fixed = 0;
  if (flags.fix && (blocked || flagged)) {
    if (apiKey) {
      if (!flags.json) console.log(dim('\n  Fixing flagged artifacts…'));
      for (const r of results) {
        if (r.decision === 'ALLOW') continue;
        const done = await fixOneFile(r.full, { apiKey, url, flags: { ...flags, apply: true, quiet: flags.json } });
        if (done) fixed++;
      }
    } else if (!flags.json) {
      console.error(`  ${yellow('⚠')} ${dim('--fix needs enrollment (the fix runs on the platform). Run')} ${bold('shomra init')}${dim('.')}`);
    }
  }

  const strictOutage = backendDown && flags.strict;
  if (flags.json) {
    console.log(JSON.stringify({ scanned: results.length, blocked, flagged, suppressed, fixed, backendDown, environment: env.environment, results }, null, 2));
  } else {
    console.log(
      '\n  ' +
        (blocked
          ? red(`✗ ${blocked} blocked`) + dim(` · ${flagged} flagged · ${results.length - blocked - flagged} clean`)
          : flagged
            ? yellow(`⚠ ${flagged} flagged`) + dim(` · ${results.length - flagged} clean`)
            : green(`✓ All ${results.length} clean.`)) +
        (suppressed ? dim(` · ${suppressed} suppressed`) : '') +
        (backendDown ? yellow('  (on-machine only — org policy not applied)') : ''),
    );
    if (flags.fix && fixed) console.log(`  ${green('✓')} ${dim(`applied ${fixed} fix${fixed > 1 ? 'es' : ''} — re-run`)} ${bold('shomra check')} ${dim('to confirm.')}`);
    else if (!flags.fix && (blocked || flagged)) console.log(dim('  Run ') + bold('shomra fix <file>') + dim(' or ') + bold('shomra check --fix') + dim(' to remediate.'));
    if (strictOutage) console.log(`  ${red('✗ Failing closed (--strict): backend unreachable, org policy unverified.')}`);
    console.log('');
  }

  if (blocked > 0 || strictOutage) process.exitCode = 1;
  else if (flagged > 0 && flags.strict) process.exitCode = 2;
}

// ── shomra baseline: accept everything here, so only NEW findings fail ───────
//
//   shomra baseline [dir]        # write .shomra/baseline.json of current findings
//
// Adopt Shomra on a repo that already has findings without a wall of red: record
// the current finding fingerprints (line-independent) as an accepted baseline;
// subsequent `check`/`gate` suppress those and fail only on findings introduced
// after. Commit .shomra/baseline.json so the whole team shares it. Re-run to
// refresh after you've fixed things.
async function cmdBaseline(flags, positional) {
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  const root = path.resolve(positional[0] || flags.path || '.');
  const env = detectEnv();
  const artifacts = walkArtifacts(root);
  if (!artifacts.length) {
    console.log(dim(`\n  No AI artifacts under ${root} — nothing to baseline.\n`));
    return;
  }
  if (!flags.json) process.stdout.write(dim(`  Scanning ${artifacts.length} artifact${artifacts.length > 1 ? 's' : ''} to baseline… `));
  // Capture EVERY current finding (suppression off) so the baseline is complete.
  const { results } = await gateArtifactList(artifacts, { apiKey, url, env, flags: { ...flags, json: true, 'no-suppress': true }, root });
  const fingerprints = new Set();
  for (const r of results) for (const f of r.findings || []) fingerprints.add(findingFingerprint(r.path, f));
  const dir = path.join(root, '.shomra');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'baseline.json');
  fs.writeFileSync(file, JSON.stringify({ createdAt: new Date().toISOString(), agentVersion: VERSION, count: fingerprints.size, fingerprints: [...fingerprints] }, null, 2));
  const rel = path.relative(process.cwd(), file).split(path.sep).join('/');
  if (flags.json) {
    console.log(JSON.stringify({ baseline: rel, count: fingerprints.size, artifacts: results.length }, null, 2));
    return;
  }
  console.log(green('done'));
  console.log(`\n  ${green('✓ Baseline written')} ${dim(`— ${fingerprints.size} finding(s) across ${results.length} artifact(s) accepted.`)}`);
  console.log(dim(`  ${rel} — commit it so your team shares the baseline. Only NEW findings will fail now.`) + '\n');
}

// Relative POSIX paths of AI artifacts that git reports as added/changed —
// null when this isn't a git repo (or git is unavailable). Uses --relative so
// paths line up with walkArtifacts' root-relative rels.
function gitChangedArtifacts(root, { staged }) {
  const run = (args) => {
    try {
      return execSync(`git ${args}`, { cwd: root, stdio: ['ignore', 'pipe', 'ignore'], timeout: 3000 }).toString();
    } catch {
      return null;
    }
  };
  const out = staged
    ? run('diff --cached --name-only --relative --diff-filter=ACM')
    : run('diff HEAD --name-only --relative --diff-filter=ACM');
  if (out === null) return null;
  const files = out.split('\n').map((s) => s.trim()).filter(Boolean);
  return files.filter((rel) => ARTIFACT_MATCHERS.some((m) => m.re.test(rel)));
}

// ── shomra pr: review a pull request — inline findings on the diff ───────────
//
//   shomra pr [--dry-run] [--strict] [--base <ref>] [--repo o/n] [--pr N] [--token T]
//   shomra pr --init                # scaffold .github/workflows/shomra.yml
//
// Runs in CI on a pull_request event: gates the AI artifacts CHANGED in the PR
// and posts a GitHub Check Run with inline annotations (they render right in the
// Files-changed tab — no comment spam, updates each push). A BLOCK fails the
// check (and the job); a FLAG warns (fails only with --strict). Enrolled runs
// also apply org policy and land in Gate Activity. Uses the CI's GITHUB_TOKEN —
// no GitHub App or webhook to stand up.
const PR_WORKFLOW = `name: Shomra AI Security
on: pull_request
permissions:
  contents: read
  checks: write
jobs:
  shomra:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }   # full history so the PR diff resolves
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx @shomra/agent pr
        env:
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
          SHOMRA_API_KEY: \${{ secrets.SHOMRA_API_KEY }}   # optional — applies org policy
          SHOMRA_URL: \${{ secrets.SHOMRA_URL }}           # optional — your backend
`;

function readGithubEvent() {
  try { return JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8')); } catch { return {}; }
}
async function githubApi(token, method, apiPath, body) {
  const res = await fetch(`https://api.github.com${apiPath}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json', 'User-Agent': 'shomra-agent' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`GitHub ${method} ${apiPath} → ${res.status} ${(await res.text()).slice(0, 200)}`);
  return res.json();
}
// AI artifacts changed in this PR vs its base branch (tries a few base spellings).
function gitChangedVsBase(root, base) {
  const run = (args) => { try { return execSync(`git ${args}`, { cwd: root, stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 }).toString(); } catch { return null; } };
  let out = null;
  for (const b of [`origin/${base}`, base]) {
    out = run(`diff --name-only --relative --diff-filter=ACM ${b}...HEAD`);
    if (out !== null) break;
  }
  if (out === null) out = run('diff HEAD~1 --name-only --relative --diff-filter=ACM'); // shallow fallback
  if (out === null) return null;
  const files = out.split('\n').map((s) => s.trim()).filter(Boolean);
  return files.filter((rel) => ARTIFACT_MATCHERS.some((m) => m.re.test(rel)));
}
const GH_LEVEL = { CRITICAL: 'failure', HIGH: 'failure', MEDIUM: 'warning', LOW: 'notice', INFO: 'notice' };

async function cmdPr(flags, positional) {
  // Scaffold the workflow and exit.
  if (flags.init) {
    const wf = path.resolve('.github/workflows/shomra.yml');
    if (fs.existsSync(wf) && !flags.force) { console.error(red('✗') + ` ${path.relative(process.cwd(), wf)} exists. Use ${bold('--force')}.`); process.exit(1); }
    fs.mkdirSync(path.dirname(wf), { recursive: true });
    fs.writeFileSync(wf, PR_WORKFLOW);
    console.log(`\n  ${green('✓ Wrote')} ${bold('.github/workflows/shomra.yml')} ${dim('— commit it; PRs will get an inline Shomra review.')}`);
    console.log(dim('  Optional: add ') + bold('SHOMRA_API_KEY') + dim(' as a repo secret to also apply org policy.') + '\n');
    return;
  }

  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  const ev = readGithubEvent();
  const repo = flags.repo || process.env.GITHUB_REPOSITORY;
  const token = flags.token || process.env.SHOMRA_GH_TOKEN || process.env.GITHUB_TOKEN;
  const base = flags.base || process.env.GITHUB_BASE_REF || ev.pull_request?.base?.ref || 'main';
  const headSha = flags.sha || ev.pull_request?.head?.sha || process.env.GITHUB_SHA || (() => { try { return execSync('git rev-parse HEAD', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim(); } catch { return null; } })();
  const prNumber = flags.pr || ev.pull_request?.number || (String(process.env.GITHUB_REF || '').match(/refs\/pull\/(\d+)\//) || [])[1];
  const root = path.resolve(flags.path || '.');
  const dryRun = !!flags['dry-run'];

  if (!repo || !headSha) { console.error(red('✗') + ' Not in a GitHub PR context (need GITHUB_REPOSITORY + a head sha). Pass --repo / --sha, or use --dry-run.'); process.exit(1); }
  if (!token && !dryRun) { console.error(red('✗') + ' No GitHub token. Set GITHUB_TOKEN (CI) or --token, or preview with --dry-run.'); process.exit(1); }

  // Gate the CHANGED artifacts (fall back to the whole tree if the diff won't resolve).
  const changed = gitChangedVsBase(root, base);
  const all = walkArtifacts(root);
  const artifacts = changed === null ? all : all.filter((a) => new Set(changed).has(a.rel));
  const env = detectEnv();

  if (!artifacts.length) {
    if (!flags.json) console.log(green('\n  ✓ No AI artifacts changed in this PR.\n'));
    if (token && !dryRun) await githubApi(token, 'POST', `/repos/${repo}/check-runs`, { name: 'Shomra AI Security', head_sha: headSha, status: 'completed', conclusion: 'success', output: { title: 'No AI artifacts changed', summary: 'No MCP configs, skills, rules, hooks or agent cards changed in this PR.' } }).catch((e) => console.error(dim('  check-run: ' + e.message)));
    return;
  }

  const { results, blocked, flagged, suppressed } = await gateArtifactList(artifacts, { apiKey, url, env, flags: { ...flags, json: true }, root });

  // Build inline annotations (GitHub caps a check-run at 50 per request).
  const annotations = [];
  for (const r of results) {
    for (const f of r.findings || []) {
      annotations.push({
        path: f.file || r.path,
        start_line: f.line || 1,
        end_line: f.line || 1,
        annotation_level: GH_LEVEL[f.severity] || 'warning',
        title: `${f.severity}: ${r.kind}`,
        message: [f.title, f.remediationText ? `Fix: ${f.remediationText}` : '', `Run \`shomra fix ${r.path}\` to remediate.`].filter(Boolean).join('\n'),
      });
    }
  }
  const shown = annotations.slice(0, 50);
  const conclusion = blocked ? 'failure' : flagged ? (flags.strict ? 'failure' : 'neutral') : 'success';
  const summary = [
    blocked ? `**${blocked} blocked**` : flagged ? `**${flagged} flagged**` : '**All clear**',
    `· ${results.length} artifact(s) changed · ${annotations.length} finding(s)${suppressed ? ` · ${suppressed} suppressed` : ''}`,
    '',
    '| Artifact | Kind | Verdict | Findings |',
    '| --- | --- | --- | --- |',
    ...results.map((r) => `| \`${r.path}\` | ${r.kind} | ${r.decision} | ${(r.findings || []).length} |`),
    annotations.length > 50 ? `\n_Showing first 50 of ${annotations.length} annotations._` : '',
  ].join('\n');
  const checkRun = {
    name: 'Shomra AI Security', head_sha: headSha, status: 'completed', conclusion,
    output: { title: `${blocked ? blocked + ' blocked' : flagged ? flagged + ' flagged' : 'Clean'} — ${results.length} changed artifact(s)`, summary, annotations: shown },
  };

  if (dryRun || flags.json) {
    console.log(JSON.stringify({ repo, prNumber: prNumber ?? null, headSha, base, conclusion, artifacts: results.length, findings: annotations.length, checkRun: dryRun ? checkRun : undefined }, null, 2));
  } else {
    console.log(bold(cyan('\n  Shomra pr')) + dim(` — ${repo} #${prNumber ?? '?'} · ${results.length} changed artifact(s) · ${annotations.length} finding(s)`));
  }

  if (token && !dryRun) {
    try {
      const run = await githubApi(token, 'POST', `/repos/${repo}/check-runs`, checkRun);
      if (!flags.json) console.log(`  ${conclusion === 'failure' ? red('✗') : conclusion === 'neutral' ? yellow('⚠') : green('✓')} Check run posted → ${dim(run.html_url || '')}`);
    } catch (e) {
      console.error(`  ${yellow('⚠')} ${dim('could not post check-run: ' + e.message)}`);
    }
  }

  if (blocked) process.exitCode = 1;
  else if (flagged && flags.strict) process.exitCode = 2;
}

// ── shomra fix: remediate an AI artifact in place ────────────────
//
//   shomra fix .mcp.json           # preview the AI fix (unified diff), don't write
//   shomra fix .mcp.json --apply   # write the fix back to the file
//   shomra fix .cursorrules --json # machine-readable
//
// The fix is generated on the Shomra platform (org AI key) and applied to your
// LOCAL working tree — enrollment is required. Degrades to printing the
// deterministic remediation guidance when the server has no AI configured.
async function cmdFix(flags, positional) {
  const file = positional[0];
  if (!file) {
    console.error(red('✗') + ' Usage: ' + bold('shomra fix <file> [--apply] [--kind mcp|skill|command|subagent|hook|rules] [--json]'));
    process.exit(1);
  }
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  if (!apiKey) {
    console.error('\n' + red('✗') + ' ' + bold('shomra fix') + ' needs enrollment — the fix is generated on the platform with your org AI key.');
    console.error('  ' + dim('Run ') + bold('shomra init --key shm_live_…') + dim(', or apply the guidance from ') + bold('shomra check') + dim(' by hand.\n'));
    process.exit(1);
  }
  let target = path.resolve(String(file));
  if (fs.existsSync(target) && fs.statSync(target).isDirectory()) {
    const skillMd = path.join(target, 'SKILL.md');
    if (!fs.existsSync(skillMd)) {
      console.error(red('✗') + ` ${file} is a directory with no SKILL.md — point at a file instead.`);
      process.exit(1);
    }
    target = skillMd;
  }
  if (!fs.existsSync(target)) {
    console.error(red('✗') + ` File not found: ${file}`);
    process.exit(1);
  }
  await fixOneFile(target, { apiKey, url, flags });
}

// Generate (and, with --apply, write) a fix for ONE file. Returns true when a
// fix was produced (previewed or applied), false otherwise. Reused by `check --fix`.
async function fixOneFile(target, { apiKey, url, flags }) {
  const rel = path.relative(process.cwd(), target).split(path.sep).join('/');
  let content;
  try {
    content = fs.readFileSync(target, 'utf8');
  } catch (e) {
    if (!flags.json) console.error(`  ${red('✗')} cannot read ${rel}: ${e.message}`);
    return false;
  }
  const kind = flags.kind && GATE_KINDS.includes(String(flags.kind)) ? String(flags.kind) : undefined;

  let res;
  try {
    if (!flags.json && !flags.quiet) process.stdout.write(dim(`  Generating fix for ${rel}… `));
    res = await api(url, apiKey, '/gate/fix', {
      ...(kind ? { kind } : {}),
      path: rel,
      name: rel.split('/').pop(),
      content,
    });
    if (!flags.json && !flags.quiet) console.log('');
  } catch (e) {
    if (flags.json) console.log(JSON.stringify({ path: rel, canFix: false, error: e.message }, null, 2));
    else console.error(`  ${red('✗')} ${e.message}`);
    return false;
  }

  if (flags.json) console.log(JSON.stringify({ path: rel, ...res }, null, 2));

  if (!res.canFix) {
    if (!flags.json) {
      if (res.reason === 'clean') console.log(`  ${green('✓')} ${dim(rel + ' — nothing to fix.')}`);
      else if (res.reason === 'ai-disabled') {
        console.log(`  ${yellow('⚠')} ${res.message}`);
        for (const g of res.guidance || []) {
          console.log(`     ${SEV_COLOR[g.severity](String(g.severity).padEnd(8))} ${g.title}`);
          if (g.remediationText) console.log(`     ${dim('fix: ' + g.remediationText)}`);
        }
        console.log('');
      } else console.log(`  ${yellow('⚠')} ${dim(rel + ' — ')}${res.message || 'no fix produced.'}`);
    }
    return false;
  }

  if (!flags.json) {
    printDiff(res.diff);
    if (res.explanation) console.log(`  ${dim(res.explanation)}`);
    const conf = res.confidence != null ? `  ${dim('confidence ' + Math.round(res.confidence * 100) + '%')}` : '';
    if (conf) console.log(conf);
    console.log('');
  }

  const apply = flags.apply || flags.write || flags.yes;
  if (!apply) {
    if (!flags.json) console.log(`  ${dim('Preview only — re-run with')} ${bold('--apply')} ${dim('to write this fix to ' + rel + '.')}\n`);
    return true;
  }
  try {
    fs.writeFileSync(target, res.fixedContent, 'utf8');
    if (!flags.json && !flags.quiet) {
      console.log(`  ${green('✓ Applied')} ${dim('→ ' + rel + '  (' + (res.findingCount || (res.findings || []).length) + ' finding(s) addressed)')}\n`);
    }
    return true;
  } catch (e) {
    if (!flags.json) console.error(`  ${red('✗')} could not write ${rel}: ${e.message}`);
    return false;
  }
}

// Colorized unified-diff printer (green add / red remove / cyan hunk header).
function printDiff(diff) {
  if (!diff) return;
  for (const line of String(diff).split('\n')) {
    if (line.startsWith('+') && !line.startsWith('+++')) console.log('  ' + green(line));
    else if (line.startsWith('-') && !line.startsWith('---')) console.log('  ' + red(line));
    else if (line.startsWith('@@')) console.log('  ' + cyan(line));
    else console.log('  ' + dim(line));
  }
}

// ── shomra why: understand a finding (the dev shape of "investigate") ──
//
//   shomra why .mcp.json        # plain-English why each finding matters + FP read
//   shomra why CLAUDE.md --json
//
// AI-distilled when enrolled (per-finding why + one-line exploit + true/false-
// positive call); offline it prints the on-machine findings + their fixes.
async function cmdWhy(flags, positional) {
  const file = positional[0];
  if (!file) {
    console.error(red('✗') + ' Usage: ' + bold('shomra why <file> [--kind mcp|skill|command|subagent|hook|rules] [--json]'));
    process.exit(1);
  }
  let target = path.resolve(String(file));
  if (fs.existsSync(target) && fs.statSync(target).isDirectory()) {
    const skillMd = path.join(target, 'SKILL.md');
    if (!fs.existsSync(skillMd)) {
      console.error(red('✗') + ` ${file} is a directory with no SKILL.md — point at a file instead.`);
      process.exit(1);
    }
    target = skillMd;
  }
  if (!fs.existsSync(target)) {
    console.error(red('✗') + ` File not found: ${file}`);
    process.exit(1);
  }
  const content = fs.readFileSync(target, 'utf8');
  const rel = path.relative(process.cwd(), target).split(path.sep).join('/');
  const kind = flags.kind && GATE_KINDS.includes(String(flags.kind)) ? String(flags.kind) : undefined;

  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);

  // Enrolled → AI-distilled explanation. Offline (or backend down) → local
  // findings + their fixes, so `why` always answers something.
  if (apiKey) {
    try {
      if (!flags.json) process.stdout.write(dim(`  Explaining ${rel}… `));
      const res = await api(url, apiKey, '/gate/explain', { ...(kind ? { kind } : {}), path: rel, name: rel.split('/').pop(), content });
      if (!flags.json) console.log('');
      if (flags.json) console.log(JSON.stringify({ path: rel, ...res }, null, 2));
      else printWhy(res);
      return;
    } catch (e) {
      if (!flags.json) console.log(yellow('backend unavailable') + dim(` — on-machine explanation (${e.message})`));
      // fall through to the local rationale
    }
  }
  whyLocal(content, kind, rel, flags);
}

function whyLocal(content, kind, rel, flags) {
  const local = localGate(content, { kind, path: rel });
  if (flags.json) {
    console.log(JSON.stringify({ path: rel, source: 'local', ...local }, null, 2));
    return;
  }
  console.log(bold(cyan('\n  Shomra why')) + dim(` — ${rel} · on-machine`));
  if (!local.findings.length) {
    console.log(green('\n  ✓ No findings — nothing to explain.\n'));
    return;
  }
  for (const f of local.findings) {
    const at = f.line ? dim(` (line ${f.line})`) : '';
    console.log(`\n  ${SEV_COLOR[f.severity]('●')} ${SEV_COLOR[f.severity](f.severity)}  ${bold(f.title)}${at}`);
    if (f.remediationText) console.log(`     ${dim('fix: ' + f.remediationText)}`);
  }
  console.log(dim('\n  Enroll (') + bold('shomra init') + dim(') for an AI-distilled why + false-positive read.\n'));
}

function printWhy(res) {
  console.log(bold(cyan('\n  Shomra why')) + dim(` — ${res.path}${res.aiEnabled ? '' : ' · rule rationale (AI off)'}`));
  if (res.summary) console.log('  ' + res.summary);
  if (!res.findings || !res.findings.length) {
    console.log(green('\n  ✓ Nothing to explain.\n'));
    return;
  }
  for (const f of res.findings) {
    const at = f.line ? dim(` (line ${f.line})`) : '';
    const fp = f.likelyFalsePositive ? yellow('  · likely false positive') : '';
    console.log(`\n  ${SEV_COLOR[f.severity]('●')} ${SEV_COLOR[f.severity](f.severity)}  ${bold(f.title)}${at}${fp}`);
    if (f.why) console.log(`     ${f.why}`);
    if (f.exploit) console.log(`     ${dim('exploit: ' + f.exploit)}`);
    if (f.assessment) console.log(`     ${dim(f.assessment)}`);
    if (f.remediationText) console.log(`     ${dim('fix: ' + f.remediationText)}`);
  }
  console.log('');
}

// ── shomra install-precommit: gate staged AI artifacts at commit time ──
//
//   shomra install-precommit [dir] [--force]
//
// Writes a .git/hooks/pre-commit that runs `shomra check --staged`, so a risky
// MCP config / skill / rules file is caught before it commits. A BLOCK stops the
// commit; flags warn but don't. Override once with `git commit --no-verify`.
async function cmdInstallPrecommit(flags, positional) {
  const root = path.resolve(positional[0] || '.');
  const hooksDir = gitHooksDir(root);
  if (!hooksDir) {
    console.error(red('✗') + ' Not a git repository (or git unavailable). cd into your repo first.');
    process.exit(1);
  }
  const hookPath = path.join(hooksDir, 'pre-commit');
  const marker = 'shomra check --staged';
  const managed = [
    '#!/bin/sh',
    '# Shomra — block staged AI artifacts that fail the gate before they land.',
    '# Managed by `shomra install-precommit`. Delete this file to uninstall.',
    'command -v shomra >/dev/null 2>&1 || { echo "shomra not on PATH — skipping AI-artifact gate"; exit 0; }',
    'shomra check --staged',
    'if [ "$?" -eq 1 ]; then',
    '  echo "✗ Shomra blocked a staged AI artifact — run: shomra fix <file> --apply  (or: git commit --no-verify to override)"',
    '  exit 1',
    'fi',
    'exit 0',
    '',
  ].join('\n');

  let existing = null;
  try {
    existing = fs.readFileSync(hookPath, 'utf8');
  } catch {}

  if (existing && existing.includes(marker) && !flags.force) {
    console.log(green('  ✓') + ' Shomra pre-commit hook already installed ' + dim('→ ' + hookPath));
    return;
  }
  if (existing && !existing.includes(marker) && !flags.force) {
    console.log('\n  ' + yellow('⚠') + ' A pre-commit hook already exists ' + dim('→ ' + hookPath));
    console.log('  Add this line to it, or re-run with ' + bold('--force') + ' to replace it (a backup is kept):');
    console.log('    ' + bold(marker) + '\n');
    return;
  }
  if (existing && flags.force) {
    try {
      fs.writeFileSync(hookPath + '.bak', existing);
      console.log(dim('  Backed up existing hook → ' + path.basename(hookPath) + '.bak'));
    } catch {}
  }
  fs.writeFileSync(hookPath, managed, 'utf8');
  try {
    fs.chmodSync(hookPath, 0o755);
  } catch {}
  console.log('\n  ' + green('✓ Installed') + ' Shomra pre-commit hook ' + dim('→ ' + hookPath));
  console.log(dim('  Staged AI artifacts are now gated on every commit. Override once with ') + bold('git commit --no-verify') + dim('.\n'));
}

// Resolve the repo's hooks dir (honours core.hooksPath / worktrees), creating it.
function gitHooksDir(root) {
  try {
    const dir = execSync('git rev-parse --git-path hooks', { cwd: root, stdio: ['ignore', 'pipe', 'ignore'], timeout: 3000 }).toString().trim();
    if (!dir) return null;
    const abs = path.isAbsolute(dir) ? dir : path.join(root, dir);
    fs.mkdirSync(abs, { recursive: true });
    return abs;
  } catch {
    return null;
  }
}

// ── workspace ZIP scan: static-analyze an archive of AI artifacts ────
//
//   shomra scan-zip <workspace.zip> [--project <id>] [--json]
//
// Uploads the archive to the platform's Workspace Scan (static analysis only —
// nothing in the archive is executed) and prints the per-kind report: Skills,
// slash commands, subagents, hooks, MCP configs, rules files, secret files.
// Exit codes: 0 = PASS/REVIEW, 2 = FAIL.

async function cmdScanZip(flags, positional) {
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  if (!apiKey) {
    console.error('\n' + red('✗') + ' Not configured. Run ' + bold('shomra init --key shm_live_…') + ' first.');
    process.exit(1);
  }
  const file = positional[0];
  if (!file) {
    console.error(red('✗') + ' Usage: ' + bold('shomra scan-zip <workspace.zip> [--project <id>] [--json]'));
    process.exit(1);
  }
  const target = path.resolve(String(file));
  if (!fs.existsSync(target) || !fs.statSync(target).isFile()) {
    console.error(red('✗') + ` File not found: ${file}`);
    process.exit(1);
  }
  if (!/\.zip$/i.test(target)) {
    console.error(red('✗') + ` ${file} is not a .zip archive.`);
    process.exit(1);
  }

  const buf = fs.readFileSync(target);
  const form = new FormData();
  form.append('file', new Blob([buf], { type: 'application/zip' }), path.basename(target));
  form.append('actor', `${os.hostname()}/${os.userInfo().username}`);
  if (flags.project) form.append('projectId', String(flags.project));

  if (!flags.json) process.stdout.write(dim('\n  Uploading to Workspace Scan… '));
  let res;
  try {
    const r = await fetch(`${url}/bundle/agent-scan`, {
      method: 'POST',
      headers: { 'X-Shomra-Key': apiKey, Connection: 'close' },
      body: form,
    });
    const text = await r.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = { raw: text };
    }
    if (!r.ok) {
      const msg = json?.message || json?.raw || r.statusText;
      throw new Error(`${r.status} ${Array.isArray(msg) ? msg.join(', ') : msg}`);
    }
    res = json;
  } catch (e) {
    if (!flags.json) console.log(red('failed'));
    console.error(`  ${red('✗')} ${e.message}\n`);
    process.exit(1);
  }
  if (!flags.json) console.log(green('done'));

  if (flags.json) {
    console.log(JSON.stringify(res, null, 2));
  } else {
    const vc = VERDICT_COLOR[res.verdict] || gray;
    console.log(`\n  ${bold(res.filename)} ${dim(`· ${res.fileCount} files · ${res.artifactCount} AI artifact(s)`)}`);
    console.log(`  ${vc('●')} ${vc(bold(res.verdict))} ${dim(`risk ${res.riskScore}/100 · ${res.findingCount} finding(s) · ${res.criticalCount} critical · ${res.highCount} high`)}`);
    if (res.policyDecision && res.policyDecision !== 'ALLOW') {
      const pc = res.policyDecision === 'BLOCK' ? red : yellow;
      const which = (res.policyHits || []).map((h) => h.policy).slice(0, 3).join(', ');
      console.log(`  ${pc('▎')} ${pc('org policy: ' + res.policyDecision)}${which ? dim(' — ' + which) : ''}`);
    }
    for (const g of res.groups || []) {
      if (!g.count) continue;
      console.log(`\n  ${bold(g.kind.replace(/_/g, ' ').toLowerCase())} ${dim(`(${g.count})`)}`);
      for (const a of g.artifacts || []) {
        const avc = VERDICT_COLOR[a.verdict] || gray;
        console.log(`    ${avc('●')} ${bold(a.name)} ${dim(a.path)} ${avc(a.verdict)} ${dim('risk ' + a.riskScore)}`);
        for (const f of (a.findings || []).filter((x) => x.severity !== 'INFO')) {
          console.log(`        ${SEV_COLOR[f.severity](String(f.severity).padEnd(8))} ${f.title}`);
        }
      }
    }
    console.log(
      '\n  ' +
        (res.verdict === 'FAIL'
          ? red('✗ Do not install this workspace unreviewed.')
          : res.verdict === 'REVIEW'
            ? yellow('⚠ Review the findings above before trusting this workspace.')
            : green('✓ Clean.')) +
        dim(' Full report in the Shomra dashboard → Workspace Scan.\n'),
    );
  }
  // Org policy takes precedence for CI: a BLOCK fails the build (exit 1), above
  // the severity-only FAIL (exit 2). A policy FLAG fails only with --strict.
  if (res.policyDecision === 'BLOCK') process.exitCode = 1;
  else if (res.verdict === 'FAIL') process.exitCode = 2;
  else if (res.policyDecision === 'FLAG' && flags.strict) process.exitCode = 2;
}

// ── model SAST scan: analyze a public AI model's source code ─────────
//
//   shomra model-scan <hf-url | owner/model | github-url> [--project <id>] [--json]
//
// Runs the platform's MODEL engine: pulls the model's source (Hugging Face Hub
// API or a shallow GitHub clone — never the weights) and runs SAST over its
// .py files + config.json, plus provenance/weight/card checks. Prints the
// per-asset findings with rule id, file:line and code snippet. Nothing is
// executed. Exit codes: 0 = PASS/REVIEW, 2 = FAIL.

async function cmdModelScan(flags, positional) {
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  if (!apiKey) {
    console.error('\n' + red('✗') + ' Not configured. Run ' + bold('shomra init --key shm_live_…') + ' first.');
    process.exit(1);
  }
  const target = positional[0];
  if (!target) {
    console.error(red('✗') + ' Usage: ' + bold('shomra model-scan <hf-url | owner/model | github-url> [--project <id>] [--json]'));
    process.exit(1);
  }

  process.stdout.write(dim(`\n  Scanning ${target}… `));
  let res;
  try {
    res = await api(url, apiKey, '/projects/agent-model-scan', {
      target: String(target),
      actor: `${os.hostname()}/${os.userInfo().username}`,
      ...(flags.project ? { projectId: String(flags.project) } : {}),
    });
  } catch (e) {
    console.log(red('failed'));
    console.error(`  ${red('✗')} ${e.message}\n`);
    process.exit(1);
  }
  console.log(green('done'));

  if (flags.json) {
    console.log(JSON.stringify(res, null, 2));
    if (res.verdict === 'FAIL') process.exitCode = 2;
    return;
  }

  const vc = VERDICT_COLOR[res.verdict] || gray;
  console.log(`\n  ${bold(res.target || target)} ${dim(`· ${res.scanType} scan`)}`);
  console.log(
    `  ${vc('●')} ${vc(bold(res.verdict))} ${dim(
      `risk ${res.riskScore}/100 · ${res.vulnCount} finding(s) · ${res.criticalCount} critical · ${res.highCount} high`,
    )}`,
  );

  for (const a of res.assets || []) {
    const vulns = (a.vulnerabilities || []).filter((v) => v.severity !== 'INFO');
    if (!vulns.length) continue;
    console.log(`\n  ${bold(a.name)} ${dim(`(${a.assetType})`)}`);
    for (const v of vulns) {
      const ev = v.evidence && v.evidence.analysis === 'sast' ? v.evidence : null;
      console.log(`    ${SEV_COLOR[v.severity](String(v.severity).padEnd(8))} ${v.title}`);
      if (ev) {
        console.log(`        ${dim(`${ev.ruleId} · ${ev.file}:${ev.line} · sink ${ev.sink}${ev.source ? ' · source ' + ev.source : ''}`)}`);
        if (ev.snippet) console.log(`        ${gray(ev.snippet)}`);
      }
    }
  }

  // Safer, lower-risk alternatives in the same category — best-effort, only when
  // the scanned model is also in the public Model Security Index.
  if (res.verdict === 'FAIL' || res.verdict === 'REVIEW') {
    const mid = hfModelIdFromTarget(String(res.target || target));
    if (mid) {
      try {
        const look = await modelLookup(url, mid);
        if (look && Array.isArray(look.alternatives) && look.alternatives.length) {
          console.log('\n  ' + bold('Safer alternatives') + dim(' (same category, lower risk):'));
          printAlternatives(look.alternatives, 'model', '    ');
        }
      } catch { /* index enrichment is best-effort — never fail the scan on it */ }
    }
  }

  console.log(
    '\n  ' +
      (res.verdict === 'FAIL'
        ? red('✗ Do not load this model unreviewed.')
        : res.verdict === 'REVIEW'
          ? yellow('⚠ Review the findings above before trusting this model.')
          : green('✓ No high-severity issues found.')) +
      dim(' Full report in the Shomra dashboard → Projects.\n'),
  );

  if (res.verdict === 'FAIL') process.exitCode = 2;
}

// Normalize a model-scan target (HF URL, owner/model, or github URL) to the
// "owner/name" id the Model Security Index looks up by. Returns null when the
// target isn't an HF-style id (e.g. a bare github repo we can't map).
function hfModelIdFromTarget(target) {
  const t = String(target || '').trim();
  const hf = t.match(/huggingface\.co\/([^/\s?#]+\/[^/\s?#]+)/i);
  if (hf) return hf[1];
  if (/^[\w.-]+\/[\w.-]+$/.test(t) && !/github\.com/i.test(t)) return t; // owner/model
  return null;
}

// ── memory integrity: scan + track persistent agent memory ──────────
//
//   shomra memory-scan [path] [--scope project|user|global] [--writer AGENT|HUMAN|HOOK|TOOL] [--project <id>] [--json]
//
// Scans persistent agent-memory stores (MEMORY.md, .claude/memory/…, mem0 data)
// AND rules/instruction files (CLAUDE.md, AGENTS.md, .cursorrules, …) for context
// poisoning (OWASP ASI06) — injected standing directives, authority spoofing,
// staged payloads, exfil sinks — and reports each write to the platform with
// provenance so the integrity timeline, drift detection and rollback work. Rules
// files are graded against an instruction baseline (their path decides the mode).
// Point it at a repo/dir or a single file. Exit: 0 = clean/review, 2 = poisoned.

const MEMORY_MATCHERS = [
  /(^|\/)MEMOR(Y|IES)\.(md|json|jsonl|txt)$/i,
  /(^|\/)memor(y|ies)\/[^/]+\.(md|mdx|json|jsonl|txt|ya?ml)$/i,
  /(^|\/)\.(mem0|letta|memgpt)\/[^/]+\.(md|json|jsonl|txt)$/i,
];

// Rules / instruction files. These re-inject as high-authority trusted context
// every session and are increasingly agent-mutable (Claude Code `#`/`/init`,
// Cursor/Cline auto-rule writes), so they share memory's poisoning + drift
// surface (OWASP ASI06). The platform grades them against an instruction
// baseline — standing directives are legitimate; only hijack/conceal/exfil
// phrasing is poison. Mirrors the backend detector's rules-file matching.
const INSTRUCTION_MATCHERS = [
  /(^|\/)(CLAUDE|AGENTS?|GEMINI|CONVENTIONS)\.md$/i,
  /(^|\/)LLMS(-FULL)?\.txt$/i,
  /(^|\/)\.(cursorrules|windsurfrules|clinerules|aiderrules|continuerules|goosehints)$/i,
  /(^|\/)\.github\/copilot-instructions\.md$/i,
  /(^|\/)copilot-instructions\.md$/i,
  /(^|\/)\.cursor\/rules\/.+\.mdc$/i,
  /(^|\/)\.clinerules\/.+\.md$/i,
];

function isMemoryPath(p) {
  const rel = String(p || '').split(path.sep).join('/');
  return MEMORY_MATCHERS.some((re) => re.test(rel)) || INSTRUCTION_MATCHERS.some((re) => re.test(rel));
}

function walkMemoryFiles(root) {
  const found = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (!SKIP_DIRS.has(ent.name)) stack.push(full);
        continue;
      }
      const rel = path.relative(root, full).split(path.sep).join('/');
      if (isMemoryPath(rel) || isMemoryPath(full)) found.push({ full, rel });
    }
  }
  return found;
}

// Fire-and-forget provenance report of a memory write (used by the PreToolUse
// hook). Best-effort, short-timeout, never affects the caller's flow.
async function reportMemoryWrite(url, apiKey, body) {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), guardTimeoutMs());
    await fetch(`${url}/memory/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shomra-Key': apiKey, Connection: 'close' },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    clearTimeout(timer);
  } catch {
    /* memory tracking is best-effort — never disrupt the tool call */
  }
}

async function cmdMemoryScan(flags, positional) {
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  if (!apiKey) {
    console.error('\n' + red('✗') + ' Not configured. Run ' + bold('shomra init --key shm_live_…') + ' first.');
    process.exit(1);
  }
  const targetArg = positional[0] || '.';
  const target = path.resolve(String(targetArg));
  if (!fs.existsSync(target)) {
    console.error(red('✗') + ` Not found: ${targetArg}`);
    process.exit(1);
  }
  const files = fs.statSync(target).isDirectory()
    ? walkMemoryFiles(target)
    : [{ full: target, rel: path.basename(target) }];

  if (!files.length) {
    if (flags.json) console.log(JSON.stringify({ scanned: 0, stores: [] }, null, 2));
    else console.log(dim(`\n  No memory or rules files found under ${target}.\n  (Looked for MEMORY.md, memory/ dirs, .mem0/.letta stores, and rules files: CLAUDE.md, AGENTS.md, .cursorrules, copilot-instructions.md, …)\n`));
    return;
  }

  const scope = flags.scope ? String(flags.scope).toLowerCase() : undefined;
  const writer = flags.writer ? String(flags.writer).toUpperCase() : 'AGENT';
  const actor = `${os.hostname()}/${os.userInfo().username}`;
  console.log(bold(cyan('\n  Shomra Memory Integrity')) + dim(` — scanning ${files.length} store${files.length > 1 ? 's' : ''}`));

  let worst = 'PASS';
  const stores = [];
  for (const f of files) {
    let content;
    try {
      const stat = fs.statSync(f.full);
      if (stat.size > MAX_ARTIFACT_BYTES) {
        console.log(`  ${gray('•')} ${dim(f.rel)} ${yellow('skipped (too large)')}`);
        continue;
      }
      content = fs.readFileSync(f.full, 'utf8');
    } catch {
      continue;
    }
    let res;
    try {
      res = await api(url, apiKey, '/memory/ingest', {
        scope,
        path: f.rel,
        name: path.basename(f.rel),
        content,
        writer,
        source: 'shomra memory-scan',
        actor,
        ...(flags.project ? { projectId: String(flags.project) } : {}),
      });
    } catch (e) {
      console.log(`  ${red('✗')} ${f.rel} ${red('ingest error: ' + e.message)}`);
      continue;
    }
    const v = res?.store?.verdict || 'PASS';
    if (v === 'FAIL') worst = 'FAIL';
    else if (v === 'REVIEW' && worst !== 'FAIL') worst = 'REVIEW';
    stores.push({ path: f.rel, ...res });

    const vc = VERDICT_COLOR[v] || gray;
    const poison = res?.store?.poisonScore ?? 0;
    const anom = res?.provenance?.anomalous;
    console.log(
      `\n  ${vc('●')} ${bold(path.basename(f.rel))} ${dim(f.rel)} ${vc(v)} ${dim('poison ' + poison + '/100')}` +
        (res?.quarantined ? ' ' + red('QUARANTINED') : '') +
        (anom ? ' ' + red('OUT-OF-BAND WRITE') : ''),
    );
    for (const finding of (res?.analysis?.findings || []).filter((x) => x.severity !== 'INFO')) {
      console.log(`      ${SEV_COLOR[finding.severity](String(finding.severity).padEnd(8))} ${finding.title}`);
    }
    if (anom) console.log(`      ${red('provenance:')} ${dim(res.provenance.reason)}`);
  }

  if (flags.json) {
    console.log(JSON.stringify({ scanned: stores.length, worst, stores }, null, 2));
  } else {
    console.log(
      '\n  ' +
        (worst === 'FAIL'
          ? red('✗ Memory poisoning detected — roll back the affected stores.')
          : worst === 'REVIEW'
            ? yellow('⚠ Review the flagged memory before the agent reloads it.')
            : green('✓ No memory poisoning found.')) +
        dim(' Full timeline + rollback in the Shomra dashboard → Memory.\n'),
    );
  }
  if (worst === 'FAIL') process.exitCode = 2;
}

// ── continuous agentic red-teaming: prove your guardrails still hold ────
//
//   shomra redteam [--target llm-guard|model] [--scenarios goal-hijack,jailbreak]
//                  [--min 80] [--fail-on-regression] [--project <id>] [--json]
//
// Replays the adversarial scenario library against your OWN LLM Guard (probe
// mode — nothing is persisted as a real attack) or model, scores resilience,
// and flags regressions vs the previous run. Great in CI: gate a merge/deploy
// on `--min <resilience>` and/or `--fail-on-regression`. Exit: 0 = pass,
// 2 = below the resilience floor or a regression appeared.

async function cmdRedteam(flags) {
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  if (!apiKey) {
    console.error('\n' + red('✗') + ' Not configured. Run ' + bold('shomra init --key shm_live_…') + ' first.');
    process.exit(1);
  }
  const targetKind = flags.target === 'model' ? 'model' : 'llm-guard';
  const scenarioKeys = typeof flags.scenarios === 'string' ? flags.scenarios.split(',').map((s) => s.trim()).filter(Boolean) : undefined;

  process.stdout.write(dim(`\n  Red-teaming your ${targetKind === 'model' ? 'model' : 'LLM Guard'}… `));
  let run;
  try {
    run = await api(url, apiKey, '/redteam/agent-run', {
      targetKind,
      ...(scenarioKeys ? { scenarioKeys } : {}),
      ...(flags.project ? { projectId: String(flags.project) } : {}),
      ...(flags.evolve ? { evolutionary: true } : flags.adaptive ? { adaptive: true } : {}),
      actor: `${os.hostname()}/${os.userInfo().username}`,
    });
  } catch (e) {
    console.log(red('failed'));
    console.error(`  ${red('✗')} ${e.message}\n`);
    process.exit(1);
  }
  console.log(green('done'));

  if (flags.json) {
    console.log(JSON.stringify(run, null, 2));
  } else {
    const rc = run.resilience >= 80 ? green : run.resilience >= 60 ? yellow : red;
    console.log(`\n  ${bold(run.label)} ${dim(`· ${run.targetKind} · ${run.scenarioCount} scenarios · ${run.attemptCount} attempts`)}`);
    console.log(`  ${rc('●')} Resilience ${rc(bold(run.resilience + '/100'))} ${dim(`· ${run.breachedCount} breached · ${run.blockedCount} blocked${run.regressedCount ? ' · ' : ''}`)}${run.regressedCount ? red(run.regressedCount + ' regressed') : ''}`);
    for (const r of (run.results || []).filter((x) => x.breached)) {
      console.log(`     ${red('✗')} ${bold(r.title)} ${dim(r.technique)} ${r.regressed ? red('· REGRESSED') : ''}`);
    }
    const held = (run.results || []).filter((x) => !x.breached).length;
    if (held) console.log(`     ${green('✓')} ${dim(`${held} scenario(s) held`)}`);
    console.log(
      '\n  ' +
        (run.breachedCount === 0
          ? green('✓ All scenarios defended.')
          : yellow(`⚠ ${run.breachedCount} scenario(s) breached your defenses.`)) +
        dim(' Full report in the Shomra dashboard → Red Team.\n'),
    );
  }

  // CI gate: fail on a resilience floor and/or any regression.
  const min = flags.min != null ? parseInt(flags.min, 10) : null;
  const belowFloor = Number.isFinite(min) && run.resilience < min;
  const regressed = flags['fail-on-regression'] && run.regressedCount > 0;
  if (belowFloor) console.error(red(`  ✗ Resilience ${run.resilience} is below the required ${min}.`));
  if (regressed) console.error(red(`  ✗ ${run.regressedCount} scenario(s) regressed since the last run.`));
  if (belowFloor || regressed) process.exitCode = 2;
}

// ── adversary campaigns: autonomous multi-turn red-team operator ──────────
//
//   shomra campaign [--objectives exfil-canary,tool-abuse] [--turns 6]
//                   [--min 80] [--project <id>] [--json]
//
// Runs an AUTONOMOUS attacker that pursues a concrete goal (exfiltrate a secret,
// trigger a dangerous tool, leak the system prompt, poison memory) over a
// multi-turn conversation with an assistant sitting behind your OWN LLM Guard,
// adapting each turn to how the guard and the assistant responded. A breach
// needs the whole chain to fail — the guard allows the turn AND the assistant
// complies — which single-prompt scans can't surface. Needs AI configured.
// Exit: 0 = pass, 2 = below the resilience floor.

async function cmdCampaign(flags) {
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  if (!apiKey) {
    console.error('\n' + red('✗') + ' Not configured. Run ' + bold('shomra init --key shm_live_…') + ' first.');
    process.exit(1);
  }
  const objectiveKeys = typeof flags.objectives === 'string' ? flags.objectives.split(',').map((s) => s.trim()).filter(Boolean) : undefined;
  const turns = flags.turns != null ? parseInt(flags.turns, 10) : undefined;

  process.stdout.write(dim('\n  Running an autonomous adversary campaign against your assistant… '));
  let run;
  try {
    run = await api(url, apiKey, '/redteam/agent-campaign', {
      ...(objectiveKeys ? { objectiveKeys } : {}),
      ...(Number.isFinite(turns) ? { turns } : {}),
      ...(flags.project ? { projectId: String(flags.project) } : {}),
      actor: `${os.hostname()}/${os.userInfo().username}`,
    });
  } catch (e) {
    console.log(red('failed'));
    console.error(`  ${red('✗')} ${e.message}\n`);
    process.exit(1);
  }
  console.log(green('done'));

  if (flags.json) {
    console.log(JSON.stringify(run, null, 2));
  } else {
    const rc = run.resilience >= 80 ? green : run.resilience >= 60 ? yellow : red;
    console.log(`\n  ${bold(run.label)} ${dim(`· ${run.scenarioCount} objective(s) · ${run.attemptCount} turns fired`)}`);
    console.log(`  ${rc('●')} Resilience ${rc(bold(run.resilience + '/100'))} ${dim(`· ${run.breachedCount} objective(s) achieved · ${run.blockedCount} turn(s) blocked by the guard`)}`);
    for (const r of (run.results || []).filter((x) => x.breached)) {
      const bt = (r.evidenceJson?.outcomes || []).filter((o) => o.breached).map((o) => o.index + 1);
      const inTurns = bt.length ? Math.min(...bt) : r.attempts;
      console.log(`     ${red('✗')} ${bold(r.title)} ${dim(`${r.technique} · achieved in ${inTurns} turn(s)`)}`);
    }
    const held = (run.results || []).filter((x) => !x.breached).length;
    if (held) console.log(`     ${green('✓')} ${dim(`${held} objective(s) defended`)}`);
    console.log(
      '\n  ' +
        (run.breachedCount === 0
          ? green('✓ Every objective was defended.')
          : yellow(`⚠ ${run.breachedCount} objective(s) achieved by the autonomous attacker.`)) +
        dim(' Full transcript in the Shomra dashboard → Red Team. Harden the guard against the winning turns.\n'),
    );
  }

  const min = flags.min != null ? parseInt(flags.min, 10) : null;
  if (Number.isFinite(min) && run.resilience < min) {
    console.error(red(`  ✗ Resilience ${run.resilience} is below the required ${min}.`));
    process.exitCode = 2;
  }
}

// ── self-hardening flywheel: red-team → propose → verify → apply ──────────
//
// `shomra harden` closes the loop the red-team opens. It runs a red-team (or
// reuses one with --run), asks the platform to propose high-precision detection
// signatures for whatever breached, verifies each against a benign corpus (must
// catch the attack AND cause zero false positives), and — with --apply — pushes
// the survivors live as a SignaturePack (no redeploy) and re-runs to prove the
// resilience lift. Great as a scheduled CI step after `shomra redteam`.
async function cmdHarden(flags) {
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  if (!apiKey) {
    console.error('\n' + red('✗') + ' Not configured. Run ' + bold('shomra init --key shm_live_…') + ' first.');
    process.exit(1);
  }
  const targetKind = flags.target === 'model' ? 'model' : 'llm-guard';
  const apply = !!flags.apply;
  const runId = flags.run ? String(flags.run) : undefined;

  process.stdout.write(
    dim(`\n  ${runId ? 'Hardening from run ' + runId : 'Red-teaming your ' + (targetKind === 'model' ? 'model' : 'LLM Guard') + ', then hardening'}… `),
  );
  let res;
  try {
    res = await api(url, apiKey, '/flywheel/agent-harden', {
      ...(runId ? { runId } : {}),
      targetKind,
      apply,
      actor: `${os.hostname()}/${os.userInfo().username}`,
    });
  } catch (e) {
    console.log(red('failed'));
    console.error(`  ${red('✗')} ${e.message}\n`);
    process.exit(1);
  }
  console.log(green('done'));

  if (flags.json) {
    console.log(JSON.stringify(res, null, 2));
    return;
  }

  const sc = res.status === 'APPLIED' ? green : res.status === 'VERIFIED' ? cyan : res.status === 'REJECTED' ? yellow : red;
  console.log(`\n  ${sc('●')} ${bold(res.status)} ${dim('· ' + (res.origin === 'ai' ? 'AI-generated' : 'mined') + ((res.techniques || []).length ? ' · ' + res.techniques.join(', ') : ''))}`);
  if (res.gapTotal) {
    console.log(`  ${res.gapClosed === res.gapTotal ? green('✓') : yellow('◑')} Closes ${bold(res.gapClosed + '/' + res.gapTotal)} breaching attempts`);
  }
  console.log(
    `  ${green('✓')} ${bold(String(res.signatures))} signature(s) passed the FP-gate ` +
      dim(`· ${res.falsePositives} false positives across ${res.benignTested} benign samples`),
  );
  if (res.applied) {
    const lift = res.resilienceBefore != null && res.resilienceAfter != null ? `${res.resilienceBefore} → ${res.resilienceAfter}/100` : 'live';
    console.log(`  ${green('✓')} Applied — signatures are ${bold('live')} with no redeploy. Resilience ${bold(lift)}`);
  } else if (res.status === 'VERIFIED') {
    console.log(`  ${cyan('→')} Ready. Re-run with ${bold('--apply')} to push them live, or review in the dashboard → Self-Hardening.`);
  } else if (res.status === 'REJECTED') {
    console.log(`  ${yellow('⚠')} No candidate was both effective and false-positive-free — nothing applied.`);
  }
  console.log(dim('\n  Full detail in the Shomra dashboard → Self-Hardening.\n'));
}

// ── agent identity: register a non-human principal ───────────────────────
//
// `shomra agent-identity register` mints this agent its OWN credential
// (shm_agt_…) so the LLM proxy + runtime firewall can authenticate it as a
// distinct principal and authorize every call against its capability policy.
// Present the handle via SHOMRA_AGENT (or --agent-id); govern its capabilities,
// approve break-glass requests and revoke it (a live kill-switch) in the
// dashboard. Listing/governing is JWT-only (server.approve) — not exposed to a
// machine key — so the CLI only self-registers.
async function cmdAgentIdentity(flags, positional) {
  const sub = (positional[0] || 'register').toLowerCase();
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  if (!apiKey) {
    console.error('\n' + red('✗') + ' Not configured. Run ' + bold('shomra init --key shm_live_…') + ' first.');
    process.exit(1);
  }
  if (sub !== 'register') {
    console.error(`\n  ${red('✗')} Unknown subcommand "${sub}". Use: ${bold('shomra agent-identity register --name "…" --type coding-agent')}`);
    console.error(dim('  (List / govern / revoke identities in the dashboard → Agent Identities.)\n'));
    process.exit(1);
  }
  let res;
  try {
    res = await api(url, apiKey, '/agents/register', {
      name: flags.name ? String(flags.name) : undefined,
      slug: flags.slug ? String(flags.slug) : undefined,
      type: flags.type ? String(flags.type) : undefined,
    });
  } catch (e) {
    console.error(`\n  ${red('✗')} ${e.message}\n`);
    process.exit(1);
  }
  if (flags.json) {
    console.log(JSON.stringify(res, null, 2));
    return;
  }
  console.log(`\n  ${green('✓')} Registered agent identity ${bold(res.name)} ${dim('(' + res.slug + ' · ' + res.type + ')')}`);
  if (res.credential) {
    console.log(`\n  ${bold('Credential')} ${dim('(shown once — store it securely):')}`);
    console.log(`    ${cyan(res.credential)}`);
  }
  console.log(`\n  Present this identity so every call is authorized as it:`);
  console.log(dim(`    export SHOMRA_AGENT=${res.slug}        # or use the credential above`));
  console.log(dim(`  Then set its least-privilege capabilities in the dashboard → Agent Identities.\n`));
}

/** The agent-identity handle to present as x-shomra-agent (distinct from the
 *  coding-agent KIND resolved by resolveAgentFlag). From --agent-id or the
 *  SHOMRA_AGENT env var; null when unset (unattributed). */
function resolveAgentIdentityHandle(flags) {
  const v = (flags && flags['agent-id'] && String(flags['agent-id'])) || process.env.SHOMRA_AGENT || '';
  return v && String(v).trim() ? String(v).trim() : null;
}

// ── runtime tool-call / tool-result firewall: multi-agent hook support ────
//
// `shomra tool-guard` / `shomra result-guard` are hook handlers that a coding
// agent's OWN pre/post tool-call hook system invokes. Each agent below ships
// a genuine *blocking* hook (verified against vendor docs as of 2026-07) with
// its own config file, event names, and stdin/stdout contract:
//   claude   — Claude Code PreToolUse/PostToolUse   (.claude/settings.json)
//   codex    — OpenAI Codex CLI, mirrors Claude's shape (.codex/hooks.json)
//   gemini   — Gemini CLI BeforeTool/AfterTool       (.gemini/settings.json)
//   cursor   — Cursor beforeShellExecution/beforeMCPExecution/afterFileEdit/
//              afterMCPExecution                     (.cursor/hooks.json)
//   windsurf — Windsurf pre_run_command/pre_write_code/pre_mcp_tool_use (only
//              pre_* hooks can block; post_* are visibility-only)
//              (.windsurf/hooks.json)
//   copilot  — GitHub Copilot CLI preToolUse/postToolUse (.github/hooks/*.json)
//   cline    — Cline (VS Code) PreToolUse/PostToolUse, Claude-style grouped
//              hooks over Cline's tool names (execute_command/write_to_file/
//              use_mcp_tool)                            (.cline/hooks.json)
//   aider    — Aider has NO pre-tool-call hook API (it is a terminal pair
//              programmer, not a tool-dispatching agent). Its correct control
//              point is the model call, so install-hook routes Aider through the
//              Shomra LLM Guard proxy instead of a tool hook (.aider.conf.yml).
// `shomra install-hook --agent <name>` writes the right shape; the installed
// hook command carries `--agent <name>` so tool-guard/result-guard know which
// contract to speak at runtime. Default agent is `claude` (unqualified hooks
// installed before multi-agent support existed still work unchanged).
//
// These hook systems are new and still moving fast — if a hook silently stops
// firing after a CLI/extension update, check that agent's current docs before
// assuming Shomra is broken; each adapter is isolated below so a schema tweak
// is a small, local edit. Fail-OPEN by default (never break the session if
// the backend is down) — set SHOMRA_GUARD_STRICT=1 to fail closed.

const AGENT_LABELS = {
  claude: 'Claude Code',
  cursor: 'Cursor',
  windsurf: 'Windsurf',
  gemini: 'Gemini CLI',
  codex: 'OpenAI Codex CLI',
  copilot: 'GitHub Copilot CLI',
  cline: 'Cline',
  aider: 'Aider',
};
const AGENT_KEYS = Object.keys(AGENT_LABELS);

// The proxy base Aider (and any OpenAI-API client) should point at so its model
// traffic is screened by the Shomra LLM Guard. Overridable for a remote proxy.
const LLM_PROXY_BASE = process.env.SHOMRA_LLM_PROXY_BASE || 'http://localhost:4141/llm/openai';

function readJsonFile(file) {
  if (!fs.existsSync(file)) return {};
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    console.error(red('✗') + ` ${file} is not valid JSON — fix or move it first.`);
    process.exit(1);
  }
}
// Dedupe check for the {matcher, hooks:[{command}]} grouped shape (Claude/Codex/Gemini).
function hasGroupedHook(list, needle) {
  return Array.isArray(list) && list.some((g) => Array.isArray(g.hooks) && g.hooks.some((h) => String(h.command || '').includes(needle)));
}
// Dedupe check for the flat {command} array shape (Cursor/Windsurf).
function hasFlatHook(list) {
  return Array.isArray(list) && list.some((h) => String(h.command || '').includes('shomra '));
}

// Each installer merges Shomra's hook(s) into that agent's config file and
// returns { file, changed }. Idempotent — re-running install-hook is a no-op
// once installed.
const AGENT_INSTALLERS = {
  claude(global) {
    const dir = global ? path.join(os.homedir(), '.claude') : path.join(process.cwd(), '.claude');
    const file = path.join(dir, 'settings.json');
    const settings = readJsonFile(file);
    settings.hooks = settings.hooks || {};
    const pre = (settings.hooks.PreToolUse = settings.hooks.PreToolUse || []);
    const post = (settings.hooks.PostToolUse = settings.hooks.PostToolUse || []);
    let changed = false;
    if (!hasGroupedHook(pre, 'shomra tool-guard')) {
      pre.push({ matcher: 'Bash|Write|Edit|MultiEdit|NotebookEdit|mcp__.*', hooks: [{ type: 'command', command: 'shomra tool-guard --agent claude' }] });
      changed = true;
    }
    if (!hasGroupedHook(post, 'shomra result-guard')) {
      post.push({ matcher: 'WebFetch|WebSearch|Read|NotebookRead|mcp__.*', hooks: [{ type: 'command', command: 'shomra result-guard --agent claude' }] });
      changed = true;
    }
    if (changed) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(file, JSON.stringify(settings, null, 2));
    }
    return { file, changed };
  },

  // Codex CLI's hook shape deliberately mirrors Claude Code's.
  codex(global) {
    const dir = global ? path.join(os.homedir(), '.codex') : path.join(process.cwd(), '.codex');
    const file = path.join(dir, 'hooks.json');
    const settings = readJsonFile(file);
    const pre = (settings.PreToolUse = settings.PreToolUse || []);
    const post = (settings.PostToolUse = settings.PostToolUse || []);
    let changed = false;
    if (!hasGroupedHook(pre, 'shomra tool-guard')) {
      pre.push({ matcher: 'Bash|Write|Edit|mcp__.*', hooks: [{ type: 'command', command: 'shomra tool-guard --agent codex' }] });
      changed = true;
    }
    if (!hasGroupedHook(post, 'shomra result-guard')) {
      post.push({ matcher: 'WebFetch|WebSearch|Read|mcp__.*', hooks: [{ type: 'command', command: 'shomra result-guard --agent codex' }] });
      changed = true;
    }
    if (changed) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(file, JSON.stringify(settings, null, 2));
    }
    return { file, changed };
  },

  // Gemini CLI's hooks live under settings.json's `hooks` key, BeforeTool/AfterTool.
  gemini(global) {
    const dir = global ? path.join(os.homedir(), '.gemini') : path.join(process.cwd(), '.gemini');
    const file = path.join(dir, 'settings.json');
    const settings = readJsonFile(file);
    settings.hooks = settings.hooks || {};
    const before = (settings.hooks.BeforeTool = settings.hooks.BeforeTool || []);
    const after = (settings.hooks.AfterTool = settings.hooks.AfterTool || []);
    let changed = false;
    if (!hasGroupedHook(before, 'shomra tool-guard')) {
      before.push({ matcher: '.*', hooks: [{ type: 'command', command: 'shomra tool-guard --agent gemini' }] });
      changed = true;
    }
    if (!hasGroupedHook(after, 'shomra result-guard')) {
      after.push({ matcher: '.*', hooks: [{ type: 'command', command: 'shomra result-guard --agent gemini' }] });
      changed = true;
    }
    if (changed) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(file, JSON.stringify(settings, null, 2));
    }
    return { file, changed };
  },

  // Cursor — one array per event name (no matcher regex). Pre-execution
  // events can block; the post-* equivalents are best-effort.
  cursor(global) {
    const dir = global ? path.join(os.homedir(), '.cursor') : path.join(process.cwd(), '.cursor');
    const file = path.join(dir, 'hooks.json');
    const cfg = readJsonFile(file);
    if (cfg.version === undefined) cfg.version = 1;
    cfg.hooks = cfg.hooks || {};
    let changed = false;
    const wire = (event, command) => {
      const list = (cfg.hooks[event] = cfg.hooks[event] || []);
      if (!hasFlatHook(list)) {
        list.push({ command });
        changed = true;
      }
    };
    wire('beforeShellExecution', 'shomra tool-guard --agent cursor');
    wire('beforeMCPExecution', 'shomra tool-guard --agent cursor');
    wire('afterFileEdit', 'shomra result-guard --agent cursor');
    wire('afterMCPExecution', 'shomra result-guard --agent cursor');
    if (changed) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
    }
    return { file, changed };
  },

  // Windsurf/Cascade — only pre_* hooks can block; post_* are logged for
  // Gate Activity visibility but cannot withhold a result.
  windsurf(global) {
    const dir = global ? path.join(os.homedir(), '.codeium', 'windsurf') : path.join(process.cwd(), '.windsurf');
    const file = path.join(dir, 'hooks.json');
    const cfg = readJsonFile(file);
    cfg.hooks = cfg.hooks || {};
    let changed = false;
    const wire = (event, command) => {
      const list = (cfg.hooks[event] = cfg.hooks[event] || []);
      if (!hasFlatHook(list)) {
        list.push({ command });
        changed = true;
      }
    };
    wire('pre_run_command', 'shomra tool-guard --agent windsurf');
    wire('pre_write_code', 'shomra tool-guard --agent windsurf');
    wire('pre_mcp_tool_use', 'shomra tool-guard --agent windsurf');
    wire('post_mcp_tool_use', 'shomra result-guard --agent windsurf');
    if (changed) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
    }
    return { file, changed };
  },

  // GitHub Copilot CLI reads a directory of hook definition files — Shomra
  // drops its own, so there's no merge-with-existing-content risk.
  copilot(global) {
    const dir = global ? path.join(os.homedir(), '.copilot', 'hooks') : path.join(process.cwd(), '.github', 'hooks');
    const file = path.join(dir, 'shomra.json');
    if (fs.existsSync(file)) return { file, changed: false };
    const cfg = {
      preToolUse: [{ command: 'shomra tool-guard --agent copilot' }],
      postToolUse: [{ command: 'shomra result-guard --agent copilot' }],
    };
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
    return { file, changed: true };
  },

  // Cline (VS Code) is tool-dispatching like Claude Code, so it gets a real
  // blocking pre/post hook in the same grouped shape. Matcher covers Cline's
  // tool vocabulary (execute_command/write_to_file/replace_in_file/use_mcp_tool),
  // all of which ToolGuardService already recognises.
  cline(global) {
    const dir = global ? path.join(os.homedir(), '.cline') : path.join(process.cwd(), '.cline');
    const file = path.join(dir, 'hooks.json');
    const settings = readJsonFile(file);
    settings.hooks = settings.hooks || {};
    const pre = (settings.hooks.PreToolUse = settings.hooks.PreToolUse || []);
    const post = (settings.hooks.PostToolUse = settings.hooks.PostToolUse || []);
    let changed = false;
    if (!hasGroupedHook(pre, 'shomra tool-guard')) {
      pre.push({ matcher: 'execute_command|write_to_file|replace_in_file|new_rule|use_mcp_tool', hooks: [{ type: 'command', command: 'shomra tool-guard --agent cline' }] });
      changed = true;
    }
    if (!hasGroupedHook(post, 'shomra result-guard')) {
      post.push({ matcher: 'read_file|web_fetch|use_mcp_tool', hooks: [{ type: 'command', command: 'shomra result-guard --agent cline' }] });
      changed = true;
    }
    if (changed) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(file, JSON.stringify(settings, null, 2));
    }
    return { file, changed };
  },

  // Aider has no per-tool hook to intercept — the meaningful control point is
  // its LLM call. Point Aider's OpenAI-compatible base URL at the Shomra LLM
  // Guard proxy so every request/response is screened (`shomra llm-proxy` must
  // be running). We append a Shomra block to .aider.conf.yml rather than parse
  // YAML, and never duplicate it.
  aider(global) {
    const file = global ? path.join(os.homedir(), '.aider.conf.yml') : path.join(process.cwd(), '.aider.conf.yml');
    let text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    if (/#\s*shomra llm guard/i.test(text) || text.includes(LLM_PROXY_BASE)) {
      return { file, changed: false };
    }
    const block =
      `\n# --- shomra llm guard ---\n` +
      `# Routes Aider's model traffic through the Shomra LLM Guard proxy so every\n` +
      `# prompt/response is policy-screened. Requires: shomra llm-proxy (running).\n` +
      `openai-api-base: ${LLM_PROXY_BASE}\n` +
      `# --- end shomra ---\n`;
    fs.writeFileSync(file, (text.endsWith('\n') || !text ? text : text + '\n') + block);
    return { file, changed: true };
  },
};

// Normalize each agent's own hook payload into the {tool_name, tool_input,
// tool_response, cwd, session_id} shape ToolGuardService/ToolResultGuardService
// already understand (they already recognize Cursor/Cline/Aider-style tool
// names like run_terminal_cmd/create_file — see tool-guard.service.ts).
function normalizeGuardInput(agent, payload) {
  switch (agent) {
    case 'cursor': {
      if (typeof payload.command === 'string') {
        return { tool_name: 'Bash', tool_input: { command: payload.command }, cwd: payload.cwd || payload.workspace_roots?.[0], session_id: payload.conversation_id };
      }
      if (payload.tool_name || payload.tool) {
        const name = payload.tool_name || payload.tool;
        return { tool_name: String(name).startsWith('mcp') ? name : `mcp__${name}`, tool_input: payload.tool_input ?? payload.arguments, tool_response: payload.tool_response ?? payload.result, cwd: payload.cwd, session_id: payload.conversation_id };
      }
      if (typeof payload.file_path === 'string') {
        return { tool_name: 'Edit', tool_input: { file_path: payload.file_path, content: payload.content ?? payload.new_content }, cwd: payload.cwd, session_id: payload.conversation_id };
      }
      return { tool_name: payload.hook_event_name || 'unknown', tool_input: payload, session_id: payload.conversation_id };
    }
    case 'windsurf': {
      const info = payload.tool_info || {};
      if (typeof info.command_line === 'string') return { tool_name: 'Bash', tool_input: { command: info.command_line }, session_id: payload.trajectory_id };
      if (typeof info.file_path === 'string') return { tool_name: 'Edit', tool_input: { file_path: info.file_path, content: info.content }, tool_response: info.result, session_id: payload.trajectory_id };
      return { tool_name: payload.agent_action_name || 'unknown', tool_input: info, tool_response: info.result, session_id: payload.trajectory_id };
    }
    case 'copilot':
      return {
        tool_name: payload.toolName || payload.tool_name,
        tool_input: payload.toolArgs || payload.tool_input,
        tool_response: payload.toolResponse ?? payload.tool_response,
        cwd: payload.cwd,
        session_id: payload.sessionId || payload.session_id,
      };
    case 'cline': {
      // Cline names a tool in `tool`/`tool_name`/`name` and its args in
      // `tool_input`/`input`/`arguments`. MCP calls come through use_mcp_tool.
      const name = payload.tool_name || payload.tool || payload.name;
      const input = payload.tool_input ?? payload.input ?? payload.arguments ?? payload.params;
      if (name === 'use_mcp_tool') {
        const server = payload.server_name || input?.server_name || 'server';
        const mcpTool = input?.tool_name || input?.name || 'tool';
        return { tool_name: `mcp__${server}__${mcpTool}`, tool_input: input?.arguments ?? input, tool_response: payload.tool_response ?? payload.result, cwd: payload.cwd, session_id: payload.task_id || payload.session_id };
      }
      return { tool_name: name, tool_input: input, tool_response: payload.tool_response ?? payload.result, cwd: payload.cwd, session_id: payload.task_id || payload.session_id };
    }
    case 'gemini':
    case 'codex':
    case 'claude':
    case 'aider':
    default:
      return { tool_name: payload.tool_name, tool_input: payload.tool_input, tool_response: payload.tool_response, cwd: payload.cwd, session_id: payload.session_id };
  }
}

// ── tiered-guard classification (Tier 0 local vs Tier 2 escalate) ──
// Paths that ARE an AI artifact — a write here is install-time behaviour the
// server's full gate must vet against org policy (mirror of PATH_KIND server-side).
const ARTIFACT_PATH_RE = /(^|\/)(\.?mcp\.json|SKILL\.md|CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.aider\.conf\.yml|agent[-_]card\.json)$|(^|\/)\.claude\/(commands|agents)\/[^/]+\.md$|(^|\/)\.claude\/settings(\.local)?\.json$|(^|\/)\.well-known\/agent(-card)?\.json$|(^|\/)\.clinerules|(^|\/)\.github\/copilot-instructions\.md$/i;
const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'create_file', 'str_replace_editor', 'str_replace_based_edit_tool', 'write_to_file', 'replace_in_file', 'new_rule']);
const SHELL_TOOLS_RE = /^(bash|shell|sh|run_command|run_terminal_cmd|execute_command|terminal|exec)$/i;
// A tool call that reaches the network (a flow-taint EXFIL SINK) — must reach
// the server so session-scoped information-flow control can see it.
const EGRESS_TOOL_RE = /fetch|web|http|browser|request|download|curl|url|open/i;
const EGRESS_CMD_RE = /\b(curl|wget|nc|ncat|http|https|invoke-restmethod|invoke-webrequest|irm|iwr|scp|rsync|ftp|telnet)\b/i;

/** The scannable text of a tool call: shell command, written content, or args. */
function guardText(tool, input) {
  const parts = [];
  if (typeof input.command === 'string') parts.push(input.command);
  if (typeof input.cmd === 'string') parts.push(input.cmd);
  if (typeof input.script === 'string') parts.push(input.script);
  if (typeof input.content === 'string') parts.push(input.content);
  if (typeof input.new_string === 'string') parts.push(input.new_string);
  if (typeof input.new_source === 'string') parts.push(input.new_source);
  if (Array.isArray(input.edits)) parts.push(input.edits.map((e) => e?.new_string ?? '').join('\n'));
  if (!parts.length) { try { parts.push(JSON.stringify(input)); } catch { parts.push(String(input)); } }
  return parts.join('\n');
}

// ── false-positive control: path allowlist for the runtime hooks ──────────────
// The static `shomra check` honors .shomraignore; the runtime firewall didn't.
// A dev needs a friction-free way to mark files known-safe (the security tool's
// own detection source, test fixtures, generated code) so a benign pattern in
// source isn't withheld. Two layers, both keyed on the target file path: a repo
// .shomraignore and a SHOMRA_GUARD_IGNORE env glob list. Cached per root.
const _guardIgnoreCache = new Map();
function guardIgnoreGlobs(root) {
  if (_guardIgnoreCache.has(root)) return _guardIgnoreCache.get(root);
  const globs = [];
  try { for (const re of loadIgnoreRules(root).fileGlobs) globs.push(re); } catch { /* no .shomraignore */ }
  const env = process.env.SHOMRA_GUARD_IGNORE;
  if (env) for (const g of String(env).split(/[,\n]+/).map((s) => s.trim()).filter(Boolean)) { try { globs.push(globToRe(g)); } catch { /* bad glob */ } }
  _guardIgnoreCache.set(root, globs);
  return globs;
}

/** The file a tool call reads/writes, if any. */
function guardTargetPath(norm) {
  const i = norm.tool_input || {};
  const p = i.file_path ?? i.path ?? i.notebook_path ?? i.filename ?? null;
  return typeof p === 'string' && p.trim() ? p : null;
}

/** Is this file on the runtime allowlist (.shomraignore / SHOMRA_GUARD_IGNORE)? */
function guardPathAllowlisted(cwd, filePath) {
  if (!filePath) return false;
  const root = cwd || process.cwd();
  let rel;
  try { rel = path.relative(root, path.resolve(root, filePath)); } catch { rel = filePath; }
  rel = String(rel).split(path.sep).join('/');
  const base = rel.split('/').pop();
  return guardIgnoreGlobs(root).some((re) => re.test(rel) || re.test(base));
}

/**
 * Does this call need the server's authoritative check (Tier 2), or can a clean
 * local verdict stand on its own? We escalate only what the server adds value
 * over the local floor for: artifact installs (org policy), MCP calls/installs
 * (governance), agent-identity calls (authorization), and network egress (flow
 * taint). Everything else — a benign `ls`, a normal source-file edit — is
 * decided locally with zero network.
 */
function guardNeedsServer(tool, input, hasIdentity) {
  if (hasIdentity) return true; // identity authz is server-side
  if (WRITE_TOOLS.has(tool)) {
    const target = String(input.file_path ?? input.path ?? input.notebook_path ?? '').replace(/\\/g, '/');
    return ARTIFACT_PATH_RE.test(target);
  }
  if (tool && tool.startsWith('mcp__')) return true;
  if (EGRESS_TOOL_RE.test(tool || '')) return true;
  if (SHELL_TOOLS_RE.test(tool || '')) {
    const cmd = String(input.command ?? input.cmd ?? input.script ?? '');
    if (EGRESS_CMD_RE.test(cmd)) return true; // egress sink
    if (/\bmcp\s+add\b|claude\s+mcp\b|@modelcontextprotocol\b|\bmcp[-_]server\b/i.test(cmd)) return true; // MCP install
  }
  const url = input?.url ?? input?.uri ?? input?.href ?? input?.endpoint;
  if (typeof url === 'string' && url) return true; // any tool carrying a URL = egress
  return false;
}

// Deny signal each agent expects back on its PreToolUse-equivalent hook.
// Windsurf has no JSON contract — only an exit code (2 = block, stderr = reason).
function emitGuardDeny(agent, reason) {
  if (agent === 'windsurf') {
    process.stderr.write(reason);
    process.exit(2);
  }
  const bodies = {
    cursor: () => ({ permission: 'deny', user_message: reason, agent_message: reason }),
    copilot: () => ({ permissionDecision: 'deny', permissionDecisionReason: reason }),
    gemini: () => ({ decision: 'deny', reason }),
    codex: () => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } }),
    cline: () => ({ decision: 'deny', reason, hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } }),
    claude: () => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } }),
  };
  process.stdout.write(JSON.stringify((bodies[agent] || bodies.claude)()));
  process.exit(0);
}

// Block signal each agent expects back on its PostToolUse-equivalent hook.
function emitResultBlock(agent, reason) {
  // Windsurf's post_* hooks are documented as visibility-only — the finding
  // still lands in Gate Activity via the API call above, but there is no
  // signal that withholds the result from the model.
  if (agent === 'windsurf') {
    console.error(dim(reason));
    process.exit(0);
  }
  const bodies = {
    cursor: () => ({ permission: 'deny', user_message: reason, agent_message: reason }),
    copilot: () => ({ permissionDecision: 'deny', permissionDecisionReason: reason }),
    gemini: () => ({ decision: 'deny', reason }),
    codex: () => ({ decision: 'block', reason, hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: reason } }),
    cline: () => ({ decision: 'block', reason, hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: reason } }),
    claude: () => ({ decision: 'block', reason, hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: reason } }),
  };
  process.stdout.write(JSON.stringify((bodies[agent] || bodies.claude)()));
  process.exit(0);
}

// A non-blocking WARNING that surfaces to the user before the call proceeds
// (agent "ask" where supported). Used for a known-vulnerable-but-not-critical
// model load: don't hard-block, but don't let it pass silently either.
function emitGuardAsk(agent, reason) {
  const bodies = {
    cursor: () => ({ permission: 'ask', user_message: reason, agent_message: reason }),
    copilot: () => ({ permissionDecision: 'ask', permissionDecisionReason: reason }),
    gemini: () => ({ decision: 'ask', reason }),
    codex: () => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: reason } }),
    cline: () => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: reason } }),
    claude: () => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: reason } }),
  };
  // windsurf / unknown agents can't "ask" — print a visible note and allow.
  if (agent === 'windsurf' || !bodies[agent]) { process.stderr.write(reason + '\n'); process.exit(0); }
  process.stdout.write(JSON.stringify(bodies[agent]()));
  process.exit(0);
}

const MODEL_WRITE_TOOLS = ['write', 'edit', 'multiedit', 'notebookedit', 'create_file', 'str_replace_editor', 'apply_patch', 'write_file'];

/**
 * Screen a file-writing tool call for a KNOWN-VULNERABLE AI model being added to
 * the code (e.g. `from_pretrained("openai-community/gpt2")`). Runs on the content
 * about to be written, so the developer is warned BEFORE the vulnerable load
 * lands — without relying on the LLM to think to check. Local detection first
 * (zero network); only a real model reference triggers the index lookup. Emits an
 * "ask" (exits) when a flagged model is found; otherwise returns to let the normal
 * flow continue. Disable with SHOMRA_MODEL_GUARD=0.
 */
async function screenModelLoad(agent, tool, input, url) {
  if (process.env.SHOMRA_MODEL_GUARD === '0' || String(process.env.SHOMRA_MODEL_GUARD).toLowerCase() === 'false') return;
  if (!MODEL_WRITE_TOOLS.includes(String(tool).toLowerCase())) return;
  const filePath = input.file_path || input.path || input.filePath;
  if (!filePath || !isModelRefScannable(filePath)) return;
  let content = '';
  if (typeof input.content === 'string') content = input.content;
  else if (typeof input.new_string === 'string') content = input.new_string;
  else if (typeof input.new_str === 'string') content = input.new_str;
  else if (Array.isArray(input.edits)) content = input.edits.map((e) => e.new_string || e.new_str || '').join('\n');
  if (!content) return;
  const refs = scanModelRefs(content, path.basename(String(filePath))).filter((r) => r.source === 'hf');
  if (!refs.length) return; // modelLookup is cache-first + breaker-aware, so don't bail here

  const flagged = [];
  for (const r of refs) {
    let lk;
    try { lk = await modelLookup(url, r.id, r.revision); } catch { return; } // uncached + backend down → can't judge, stay silent
    const findings = (lk && lk.findings) || [];
    const worst = findings.reduce((m, f) => Math.max(m, MODEL_SEV_RANK[f.severity] || 0), 0);
    const bad = lk && lk.found && (lk.verdict === 'FAIL' || lk.verdict === 'REVIEW' || worst >= MODEL_SEV_RANK.HIGH);
    if (bad) flagged.push({ id: lk.resolvedId || r.id, verdict: lk.verdict, riskScore: lk.riskScore, findings, fix: modelFixPlan(findings, lk.sha) });
  }
  if (!flagged.length) return;

  const m = flagged[0];
  const titles = m.findings.slice(0, 2).map((f) => f.title).join('; ');
  const kw = ((m.fix || {}).kwargs || []).map((k) => `${k.name}=${k.value}`).join(', ');
  const extra = flagged.length > 1 ? ` (+${flagged.length - 1} more flagged model${flagged.length - 1 === 1 ? '' : 's'})` : '';
  const reason =
    `⚠ Shomra: "${m.id}" has known vulnerabilities (${m.verdict}, risk ${m.riskScore}) — ${titles}.${extra} ` +
    `Safer: add ${kw || 'safe-loading arguments'} to the load call, pin the reviewed revision, or choose another model. (SHOMRA_MODEL_GUARD=0 to silence.)`;
  await reportGuardDecision(url, resolveSettings(loadConfig()).apiKey, null, { tool_name: tool, tool_input: { file_path: filePath }, client_decision: 'FLAG', client_reason: `vulnerable model: ${m.id}`, machine: gateMachine(), env: detectEnv(), agent });
  emitGuardAsk(agent, reason); // exits
}

function resolveAgentFlag(flags) {
  const agent = String(flags.agent || 'claude').toLowerCase();
  return AGENT_KEYS.includes(agent) ? agent : 'claude';
}

function envFlag(name) {
  return ['1', 'true', 'yes', 'on'].includes(String(process.env[name] ?? '').toLowerCase());
}

/** The gate/tool-call request body, optionally carrying the Tier-0 verdict. */
function buildGuardBody(norm, agent, clientDecision, clientReason) {
  return {
    tool_name: norm.tool_name,
    tool_input: norm.tool_input,
    cwd: norm.cwd,
    session_id: norm.session_id,
    machine: gateMachine(),
    env: detectEnv(),
    agent,
    ...(clientDecision ? { client_decision: clientDecision, client_reason: clientReason } : {}),
  };
}

/**
 * Best-effort record of a decision the local Tier-0 guard already made, so a
 * locally-blocked call still lands in Gate Activity when the backend is up.
 * Breaker-gated + short timeout so a down backend never delays the block.
 */
async function reportGuardDecision(url, apiKey, agentId, body) {
  if (!apiKey || breakerOpen()) return;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), Math.min(guardTimeoutMs(), 1000));
    await fetch(`${url}/gate/tool-call`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shomra-Key': apiKey, ...(agentId ? { 'X-Shomra-Agent': agentId } : {}), Connection: 'close' },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    breakerReset();
  } catch {
    breakerTrip();
  }
}

/**
 * Tiered pre-tool-call guard.
 *   Tier 0 (local, no network): high-confidence detectors decide the dangerous
 *     majority on-box — a CRITICAL signal BLOCKs instantly even with no backend,
 *     no API key, or a blocked network. This is the un-DoS-able floor.
 *   Tier 2 (server): only policy-relevant calls (artifact installs, MCP calls,
 *     agent-identity, network egress, or anything Tier 0 FLAGged) escalate for
 *     the full org-policy / identity / governance / flow engine.
 *   Skip: benign, locally-cleared, non-policy-relevant calls allow with ZERO
 *     network — that's the bulk of calls and the whole overhead problem.
 */
async function cmdToolGuard(flags) {
  const agent = resolveAgentFlag(flags);
  const agentId = resolveAgentIdentityHandle(flags);
  const strict = envFlag('SHOMRA_GUARD_STRICT');
  const localOff = process.env.SHOMRA_GUARD_LOCAL === '0' || String(process.env.SHOMRA_GUARD_LOCAL).toLowerCase() === 'false';
  const alwaysEscalate = envFlag('SHOMRA_GUARD_ALWAYS_ESCALATE');
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);

  let payload = {};
  try {
    payload = JSON.parse(fs.readFileSync(0, 'utf8') || '{}');
  } catch {
    process.exit(0); // unparseable input — don't block the session
  }

  const norm = normalizeGuardInput(agent, payload);
  const tool = (norm.tool_name ?? '').trim();
  const input = norm.tool_input ?? {};

  // ── Tier 0: local, in-process, zero-network ──
  let local = { verdict: 'ALLOW', top: null, findings: [] };
  if (!localOff) {
    const scan = localScan(guardText(tool, input));
    // File WRITES screen content: a pattern living in a string / regex / comment
    // is a rule or a sample, not a live command — down-rank so editing detection
    // source or fixtures isn't blocked. Shell commands stay strict (a quoted
    // payload still runs). An explicitly allowlisted path is skipped entirely.
    const isWrite = WRITE_TOOLS.has(tool);
    const allow = isWrite && guardPathAllowlisted(norm.cwd, guardTargetPath(norm));
    const findings = allow ? [] : isWrite ? downrankCodeContext(scan.findings) : scan.findings;
    local = { ...grade(findings), top: findings.find((f) => f.severity === 'CRITICAL') || findings[0] || null, findings };
    if (local.verdict === 'BLOCK') {
      const reason = `Blocked on-machine by Shomra: ${local.top?.label || 'dangerous tool call'}.`;
      await reportGuardDecision(url, apiKey, agentId, buildGuardBody(norm, agent, 'BLOCK', local.top?.label));
      emitGuardDeny(agent, reason); // exits
    }
  }

  // Model-load safety: if this write ADDS a known-vulnerable AI model, warn (ask)
  // before it lands — deterministic, not dependent on the LLM choosing to check.
  // Uses the public model index, so it works even before enrollment.
  await screenModelLoad(agent, tool, input, url);

  // No key → nothing to escalate to; the local floor already ran (unbreakable).
  if (!apiKey) {
    if (strict) emitGuardDeny(agent, 'Shomra is not configured on this machine (SHOMRA_GUARD_STRICT). Run: shomra init --key shm_…');
    process.exit(0);
  }

  // Memory integrity: capture a persistent-memory write (AGENT provenance) for
  // the integrity timeline / drift / poison analysis. Best-effort, breaker-gated.
  const memPath = input.file_path || input.path;
  if (memPath && isMemoryPath(memPath) && !breakerOpen()) {
    const memContent =
      typeof input.content === 'string' ? input.content
      : typeof input.new_string === 'string' ? input.new_string : null;
    if (memContent != null) {
      await reportMemoryWrite(url, apiKey, {
        path: String(memPath).split(path.sep).join('/'),
        name: path.basename(String(memPath)),
        content: memContent,
        writer: 'AGENT',
        source: os.hostname(),
        actor: os.userInfo().username,
        sessionId: norm.session_id,
      });
    }
  }

  // ── Decide escalation to Tier 2 ──
  const escalate = alwaysEscalate || local.verdict === 'FLAG' || guardNeedsServer(tool, input, !!agentId);
  if (!escalate) process.exit(0); // benign + locally-cleared + not policy-relevant → allow, no network

  // Breaker: skip the round-trip while the backend is known-down (fail-open —
  // Tier 0 already caught the dangerous cases). Strict opts out to stay closed.
  if (!strict && breakerOpen()) process.exit(0);

  const body = buildGuardBody(
    norm,
    agent,
    local.verdict === 'FLAG' ? 'FLAG' : undefined,
    local.verdict === 'FLAG' ? local.top?.label : undefined,
  );
  let res;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), guardTimeoutMs());
    const r = await fetch(`${url}/gate/tool-call`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shomra-Key': apiKey, ...(agentId ? { 'X-Shomra-Agent': agentId } : {}), Connection: 'close' },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    res = await r.json();
    breakerReset(); // healthy response — clear any tripped breaker
  } catch (e) {
    breakerTrip(); // remember this failure so the next calls skip the wait
    if (strict) emitGuardDeny(agent, `Shomra guard could not be reached (${e.message}); blocked by fail-closed policy.`);
    process.exit(0); // fail-open (Tier 0 already screened the dangerous patterns)
  }

  if (res && res.decision === 'BLOCK') {
    emitGuardDeny(agent, res.reason || 'Blocked by Shomra security policy.');
  }
  // ALLOW / FLAG → stay silent and let the agent's normal permission flow run.
  process.exit(0);
}

async function cmdResultGuard(flags) {
  const agent = resolveAgentFlag(flags);
  const strict = process.env.SHOMRA_GUARD_STRICT === '1' || process.env.SHOMRA_GUARD_STRICT === 'true';
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);

  let payload = {};
  try {
    payload = JSON.parse(fs.readFileSync(0, 'utf8') || '{}');
  } catch {
    process.exit(0); // unparseable input — don't disrupt the session
  }

  const norm = normalizeGuardInput(agent, payload);
  const response = norm.tool_response ?? payload.tool_response;
  const respText = typeof response === 'string' ? response : (() => { try { return JSON.stringify(response); } catch { return String(response ?? ''); } })();

  // ── Tier 0: local screen of the RETURNED content (indirect-injection channel)
  // — a CRITICAL injection / RCE / exfil payload in a fetched page or file read
  // is withheld on-box, even offline. The server does the nuanced flow-taint pass.
  const localOff = process.env.SHOMRA_GUARD_LOCAL === '0' || String(process.env.SHOMRA_GUARD_LOCAL).toLowerCase() === 'false';
  // Returned content is data the agent READS: a pattern inside a literal /
  // comment / fenced example is not a live instruction, so down-rank it — reading
  // detection source or docs that describe an attack must not be withheld
  // (executing it is separately gated by the pre-call firewall). An allowlisted
  // path skips screening entirely.
  const allow = guardPathAllowlisted(norm.cwd, guardTargetPath(norm));
  const scan = localScan(respText);
  const findings = allow ? [] : downrankCodeContext(scan.findings);
  const codeAware = grade(findings);
  // The block-worthy signals — a CRITICAL payload/secret, or a prompt injection —
  // are what withhold content. When every one of those sits in a code/data
  // context (a rule definition, a quoted sample, a fenced/commented example) the
  // returned content is source or docs, not a live directive: suppress the
  // withhold, including the server's regex-only block (still recorded server-side
  // for visibility). Detector over-matches on benign code (a `.exec()` call, a
  // `||`) are HIGH-shell noise, not injection/critical, so they don't force a
  // block. A real non-code injection or CRITICAL keeps it.
  const nonCodeCritical = scan.findings.some((f) => f.severity === 'CRITICAL' && !f.codeContext);
  const nonCodeInjection = scan.findings.some((f) => f.category === 'injection' && !f.codeContext);
  const suppressBlock = allow || (scan.findings.length > 0 && !nonCodeCritical && !nonCodeInjection);
  if (!localOff && !suppressBlock && codeAware.verdict === 'BLOCK') {
    const top = findings.find((f) => f.severity === 'CRITICAL') || findings[0];
    emitResultBlock(agent, `Shomra withheld this tool result (on-machine): ${top?.label || 'malicious content'}. Do not act on it.`);
  }

  if (!apiKey) {
    if (strict) emitResultBlock(agent, 'Shomra is not configured on this machine (SHOMRA_GUARD_STRICT). Run: shomra init --key shm_…');
    process.exit(0);
  }

  // Circuit breaker: skip the round-trip while the backend is known-down
  // (fail-open). Strict mode opts out to stay fail-closed.
  if (!strict && breakerOpen()) process.exit(0);

  const body = {
    tool_name: norm.tool_name,
    tool_input: norm.tool_input,
    tool_response: response,
    cwd: norm.cwd,
    session_id: norm.session_id,
    machine: gateMachine(),
    env: detectEnv(),
    agent,
  };

  let res;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), guardTimeoutMs());
    const r = await fetch(`${url}/gate/tool-result`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shomra-Key': apiKey, Connection: 'close' },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    res = await r.json();
    breakerReset();
  } catch (e) {
    breakerTrip();
    if (strict) emitResultBlock(agent, `Shomra result-guard could not be reached (${e.message}); blocked by fail-closed policy.`);
    process.exit(0); // fail-open
  }

  if (res && res.decision === 'BLOCK' && !suppressBlock) {
    emitResultBlock(agent, res.reason || 'Shomra withheld this tool result: it carries prompt injection or exfil content. Do not act on it.');
  }
  // ALLOW / FLAG (or a context-suppressed block) → stay silent; the result flows
  // to the agent as normal.
  process.exit(0);
}

// Wire the runtime firewall into one or more coding agents' hook systems.
// Default (no --agent) targets Claude Code only, unchanged from before
// multi-agent support existed. `--agent cursor,windsurf` or `--agent all`
// installs into others too.
function cmdInstallHook(flags) {
  const global = !!flags.global;
  const requested = flags.agent
    ? String(flags.agent).toLowerCase().split(',').map((s) => s.trim()).filter(Boolean)
    : ['claude'];
  const unknown = requested.filter((a) => a !== 'all' && !AGENT_KEYS.includes(a));
  if (unknown.length) {
    console.error(red('✗') + ` Unknown agent(s): ${unknown.join(', ')}. Supported: ${AGENT_KEYS.join(', ')}, all.`);
    process.exit(1);
  }
  const targets = requested.includes('all') ? AGENT_KEYS : requested;

  for (const agent of targets) {
    const { file, changed } = AGENT_INSTALLERS[agent](global);
    if (changed) {
      console.log(green('✓') + ` Installed the Shomra runtime firewall for ${bold(AGENT_LABELS[agent])} → ${bold(file)}`);
    } else {
      console.log(yellow('•') + ` Shomra runtime firewall already installed for ${AGENT_LABELS[agent]} in ${bold(file)}`);
    }
    if (agent === 'windsurf') {
      console.log(dim('    Note: Windsurf\'s post-hooks can flag/log but not withhold a tool result.'));
    }
    if (agent === 'aider') {
      console.log(dim('    Note: Aider has no tool hook — this routes its model calls through the'));
      console.log(dim('          Shomra LLM Guard proxy. Start it with ') + 'shomra llm-proxy' + dim(' and set your API key.'));
    }
  }
  console.log(dim('\n  PreToolUse:  screens every shell command, artifact write, and MCP call BEFORE it runs —'));
  console.log(dim('               and vets AI model loads the agent writes (from_pretrained / hf_hub /'));
  console.log(dim('               torch.hub …) against the Shomra Model Index, so a known-vulnerable model'));
  console.log(dim('               is flagged with its fix BEFORE the load lands. (SHOMRA_MODEL_GUARD=0 to silence.)'));
  console.log(dim('  PostToolUse: screens content fetched pages / file reads / MCP responses bring BACK'));
  console.log(dim('               into the agent context — prompt injection, exfil sinks, hidden payloads.'));
  console.log(dim('  Blocked calls/results are refused with a reason; every decision lands in Shomra → Gate Activity.'));
  console.log(dim('  Dangerous calls (curl|sh, reverse shells, secrets, injection) are blocked ON-MACHINE with'));
  console.log(dim('  no network; only policy-relevant calls escalate to the backend, so a slow/down backend'));
  console.log(dim('  never freezes the agent. Tip: ') + 'SHOMRA_GUARD_STRICT=1' + dim(' also fails-closed on the server tier.'));
}

// ── shomra doctor: "am I safe?" — one-command posture of this machine ────────
//
//   shomra doctor [--json]
//
// Discovers the AI tooling on this box (coding agents, MCP servers, rules files,
// model keys, AI tools), locally scans the scannable ones, and prints a posture
// score + the top fixes. Zero backend needed — the fastest "show a colleague"
// first-run. Pairs with `shomra protect` (unguarded agents) and `shomra check`.
function cmdDoctor(flags) {
  const assets = discoverAll();
  const by = (t) => assets.filter((a) => a.type === t);
  const agents = by('AI_AGENT'), mcps = by('MCP_SERVER'), rules = by('AI_RULES');
  const keys = by('MODEL_KEY'), tools = by('AI_TOOL');

  // Local risk scan of whatever content discovery captured (no backend).
  const risky = [];
  const scanAsset = (a, kind) => {
    const content = a.content || a.metadata?.content;
    if (!content) return;
    const g = localGate(content, { kind, path: a.metadata?.configFile || a.metadata?.file || a.name });
    if (g.verdict !== 'ALLOW') risky.push({ name: a.name, kind, decision: g.verdict, riskScore: g.riskScore, top: (g.findings[0] || {}).title });
  };
  for (const m of mcps) scanAsset(m, 'mcp');
  for (const r of rules) scanAsset(r, 'rules');

  const unguarded = agents.filter((a) => !a.metadata?.guarded);
  const dotenvKeys = keys.filter((k) => k.metadata?.source === 'dotenv');
  const blockCount = risky.filter((r) => r.decision === 'BLOCK').length;

  let score = 100;
  score -= Math.min(40, unguarded.length * 8);
  for (const r of risky) score -= r.decision === 'BLOCK' ? 15 : 5;
  score -= Math.min(30, dotenvKeys.length * 10);
  score = Math.max(0, Math.round(score));
  const g = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  const scoreColor = score >= 75 ? green : score >= 50 ? yellow : red;

  if (flags.json) {
    console.log(JSON.stringify({
      score, grade: g, hostname: os.hostname(),
      codingAgents: agents.length, unguarded: unguarded.length,
      mcpServers: mcps.length, rulesFiles: rules.length, aiTools: tools.length,
      modelKeys: keys.length, modelKeysInDotenv: dotenvKeys.length,
      riskyArtifacts: risky.length, risky,
    }, null, 2));
    return;
  }

  console.log(bold(cyan('\n  Shomra doctor')) + dim(` — ${os.hostname()}`));
  console.log(`\n  ${bold('Posture')}  ${scoreColor(bold(score + '/100'))} ${dim('· grade')} ${scoreColor(bold(g))}\n`);
  const row = (label, n, note) => console.log(`  ${dim(String(label).padEnd(16))} ${bold(String(n).padStart(3))}${note ? '  ' + note : ''}`);
  row('Coding agents', agents.length, unguarded.length ? red(`${unguarded.length} UNGUARDED`) + dim(` · ${agents.length - unguarded.length} protected`) : green('all protected'));
  row('MCP servers', mcps.length, risky.filter((r) => r.kind === 'mcp').length ? yellow(`${risky.filter((r) => r.kind === 'mcp').length} risky`) : '');
  row('Rules files', rules.length, risky.filter((r) => r.kind === 'rules').length ? yellow(`${risky.filter((r) => r.kind === 'rules').length} risky`) : '');
  row('Model keys', keys.length, dotenvKeys.length ? yellow(`${dotenvKeys.length} in .env files`) : '');
  row('AI tools', tools.length, '');

  if (risky.length) {
    console.log(dim('\n  Risky artifacts:'));
    for (const r of risky.slice(0, 6)) {
      const dc = r.decision === 'BLOCK' ? red : yellow;
      console.log(`    ${dc('●')} ${bold(r.name)} ${dim('(' + r.kind + ')')} ${dc(r.decision)} ${dim(r.top || '')}`);
    }
  }

  const fixes = [];
  if (unguarded.length) fixes.push(`${red('!')} ${unguarded.length} coding agent${unguarded.length > 1 ? 's have' : ' has'} no runtime firewall → ${bold('shomra protect')}`);
  if (risky.length) fixes.push(`${yellow('!')} ${risky.length} risky MCP/rules artifact${risky.length > 1 ? 's' : ''} → ${bold('shomra check')} ${dim('or')} ${bold('shomra gate <file>')}`);
  if (dotenvKeys.length) fixes.push(`${yellow('!')} ${dotenvKeys.length} model key${dotenvKeys.length > 1 ? 's' : ''} in .env file${dotenvKeys.length > 1 ? 's' : ''} → rotate + ensure .gitignore covers them`);
  if (fixes.length) {
    console.log(bold('\n  Top fixes:'));
    for (const f of fixes) console.log(`    ${f}`);
  } else {
    console.log(green('\n  ✓ No urgent fixes — nice posture.'));
  }
  console.log(dim(`\n  ${loadConfig().apiKey ? 'Enrolled — run ' + bold('shomra report') + dim(' to sync this to your Shomra org.') : 'Run ' + bold('shomra init') + dim(' to apply org policy and sync posture.')}`) + '\n');
}

// ── shomra protect: one command, wire the firewall for EVERY coding agent ────
//
//   shomra protect [--local] [--force]
//
// `install-hook` protects one named agent; this discovers every supported coding
// agent on the machine and wires the Pre/Post firewall for each unguarded one —
// the zero-friction "seatbelt on everything" button. Global (machine-wide) by
// default; --local scopes to this repo's .<agent> dirs.
function cmdProtect(flags) {
  const assets = discoverAll();
  const labelToKey = Object.fromEntries(Object.entries(AGENT_LABELS).map(([k, v]) => [v, k]));
  const detected = assets
    .filter((a) => a.type === 'AI_AGENT')
    .map((a) => ({ label: a.name, key: labelToKey[a.name], guarded: !!a.metadata?.guarded }))
    .filter((a) => a.key && AGENT_INSTALLERS[a.key]);

  if (!detected.length) {
    console.log(dim('\n  No supported coding agents detected on this machine.'));
    console.log(dim('  Install one (Claude Code, Cursor, Gemini/Codex/Copilot CLI, Cline, Aider…) and re-run, or force all: ') + bold('shomra install-hook --agent all') + '\n');
    return;
  }

  const global = !flags.local;
  console.log(bold(cyan('\n  Shomra protect')) + dim(` — wiring the runtime firewall for ${detected.length} coding agent${detected.length > 1 ? 's' : ''} (${global ? 'machine-wide' : 'this repo'})`));
  let wired = 0, already = 0;
  for (const a of detected) {
    if (a.guarded && !flags.force) { already++; console.log(`  ${yellow('•')} ${AGENT_LABELS[a.key]} ${dim('already protected')}`); continue; }
    try {
      const { file, changed } = AGENT_INSTALLERS[a.key](global);
      if (changed) { wired++; console.log(`  ${green('✓')} Protected ${bold(AGENT_LABELS[a.key])} ${dim('→ ' + file)}`); }
      else { already++; console.log(`  ${yellow('•')} ${AGENT_LABELS[a.key]} ${dim('already protected (' + file + ')')}`); }
      if (a.key === 'aider') console.log(dim('      Aider has no tool hook — routes model calls through the LLM Guard proxy. Start ') + bold('shomra llm-proxy') + dim('.'));
    } catch (e) {
      console.log(`  ${red('✗')} ${AGENT_LABELS[a.key]} ${dim('— ' + e.message)}`);
    }
  }
  console.log(`\n  ${wired ? green(`✓ ${wired} newly protected`) : green('✓ Already protected')}${already ? dim(` · ${already} already wired`) : ''}${dim(' — Pre/Post tool calls now screened on-machine.')}\n`);
}

// ── shomra new: scaffold a secure-by-default AI artifact ─────────────────────
//
//   shomra new skill|command|subagent|agent-card|mcp|rules [name]
//
// Generates the artifact from a least-privilege template (explicit narrow tool
// grants, env-referenced secrets, https + auth on cards) and gates it to prove
// it starts clean — "the right thing is the default thing."
const NEW_TEMPLATES = {
  skill: (name) => ({
    file: path.join(name, 'SKILL.md'),
    content: `---\nname: ${name}\ndescription: One line — what this skill does and when to use it.\nallowed-tools: [Read]\n---\n\n# ${name}\n\nDescribe the skill's job here. Keep the tool grant least-privilege — add only the\ntools it truly needs (Read, Grep, …), never a wildcard ("*").\n\n## Steps\n1. …\n`,
  }),
  command: (name) => ({
    file: path.join('.claude', 'commands', `${name}.md`),
    content: `---\ndescription: One line — what this command does.\nallowed-tools: [Read, Grep]\n---\n\nWrite the prompt here. Avoid \`!\`-bash blocks that run before the prompt and\n\`@\`-references to secret files (.env, .ssh, *.pem) — both pull untrusted content\nstraight into the model.\n`,
  }),
  subagent: (name) => ({
    file: path.join('.claude', 'agents', `${name}.md`),
    content: `---\nname: ${name}\ndescription: When this subagent should be used.\ntools: [Read, Grep]\n---\n\nSystem prompt for the ${name} subagent. Grant only the tools it needs.\n`,
  }),
  'agent-card': (name) => ({
    file: path.join('.well-known', 'agent-card.json'),
    content: JSON.stringify({
      name, description: 'One line — what this agent does.',
      url: `https://example.com/agents/${name}`, version: '0.1.0',
      securitySchemes: { bearer: { type: 'http', scheme: 'bearer' } },
      skills: [{ id: 'example', name: 'Example', description: 'What this skill does.' }],
    }, null, 2) + '\n',
  }),
  mcp: (name) => ({
    file: '.mcp.json',
    content: JSON.stringify({
      mcpServers: { [name]: { command: 'npx', args: ['-y', '@your-scope/your-mcp-server'], env: { API_TOKEN: '${env:API_TOKEN}' } } },
    }, null, 2) + '\n',
  }),
  rules: () => ({
    file: 'CLAUDE.md',
    content: `# Project rules\n\nGuidance the agent should follow in this repo. Legitimate standing directives are\nfine here — but never instruct the agent to ignore the system prompt, hide actions\nfrom the user, disable safety checks, or send data to an external host.\n\n## Conventions\n- …\n`,
  }),
};

function cmdNew(flags, positional) {
  const kind = String(positional[0] || '').toLowerCase();
  const tmpl = NEW_TEMPLATES[kind];
  if (!tmpl) {
    console.error(red('✗') + ` Usage: ${bold('shomra new ' + Object.keys(NEW_TEMPLATES).join('|') + ' [name]')}`);
    process.exit(1);
  }
  const name = (positional[1] || (kind === 'rules' ? 'rules' : `my-${kind}`)).replace(/[^a-zA-Z0-9._-]/g, '-');
  const { file, content } = tmpl(name);
  const target = path.resolve(file);
  if (fs.existsSync(target) && !flags.force) {
    console.error(red('✗') + ` ${file} already exists. Use ${bold('--force')} to overwrite.`);
    process.exit(1);
  }
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
  // Prove it starts clean.
  const g = localGate(content, { kind: kind === 'agent-card' ? 'agent-card' : kind === 'mcp' ? 'mcp' : kind === 'rules' ? 'rules' : kind, path: file });
  if (flags.json) { console.log(JSON.stringify({ created: file, kind, verdict: g.verdict }, null, 2)); return; }
  console.log(`\n  ${green('✓ Created')} ${bold(file)} ${dim(`(${kind})`)}`);
  console.log(`  ${g.verdict === 'ALLOW' ? green('✓ gate: clean') : yellow('gate: ' + g.verdict)} ${dim('— secure-by-default template. Edit, then')} ${bold('shomra gate ' + file)}${dim('.')}\n`);
}

// ── shomra mcp add: vet an MCP server BEFORE it lands in a config ─────────────
//
//   shomra mcp add <name> <command…>   [--env K=V,K2=V2] [--config <file>] [--force]
//   shomra mcp add <name> --url <url>  [--config <file>] [--force]
//   shomra mcp list                    [--config <file>]
//
// Never add an MCP server unvetted: builds the candidate config, gates it locally
// (typosquat / plaintext / static-secret / dangerous launch), and only writes it
// into the target config (default ./.mcp.json) when it passes. A BLOCK refuses
// unless --force; a FLAG warns and proceeds.
function parseEnvKV(str) {
  const env = {};
  for (const pair of String(str || '').split(',')) {
    const i = pair.indexOf('=');
    if (i > 0) env[pair.slice(0, i).trim()] = pair.slice(i + 1).trim();
  }
  return env;
}

// The best identifier to look this server up by in the MCP Security Index: the
// URL for a remote server, otherwise the launched package (skipping runners like
// npx/uvx/node and flags), falling back to the server name.
const MCP_RUNNERS = new Set(['npx', '-y', '--yes', 'uvx', 'uv', 'node', 'bun', 'deno', 'python', 'python3', '-m', 'pipx', 'run', 'npm', 'pnpm', 'yarn', 'dlx', 'bunx']);
function mcpLookupId(server, name) {
  if (server.url) return String(server.url);
  const toks = [server.command, ...(server.args || [])].filter(Boolean).map(String);
  for (const t of toks) {
    if (MCP_RUNNERS.has(t) || t.startsWith('-')) continue;
    if (/^@?[\w][\w./-]*$/.test(t)) return t; // first package-ish token
  }
  return name;
}

// Fetch a server's cached findings from the platform's MCP Security Index.
// Best-effort — never throws to the caller; a timeout/offline just returns an error.
async function mcpLookup(url, id) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), clampInt(process.env.SHOMRA_API_TIMEOUT_MS, 15000, 1000, 60000));
  try {
    const res = await fetch(`${url}/catalog/lookup?id=${encodeURIComponent(id)}`, {
      signal: ctrl.signal,
      headers: { Accept: 'application/json', 'User-Agent': 'shomra-agent' },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

/** Turn an index lookup into an alert level, or null when it can't verdict. */
function mcpIndexAlert(index) {
  if (!index || !index.found || !index.scanned) return null;
  if (index.verdict === 'FAIL' || (index.criticalCount ?? 0) > 0) return 'BLOCK';
  if (index.verdict === 'REVIEW' || (index.highCount ?? 0) > 0) return 'FLAG';
  return 'OK';
}

/** Combine the local-gate verdict with the index alert (worst wins). */
function worstMcpVerdict(local, idxAlert) {
  const rank = { ALLOW: 0, OK: 0, PASS: 0, FLAG: 1, REVIEW: 1, BLOCK: 2, FAIL: 2 };
  const label = ['ALLOW', 'FLAG', 'BLOCK'];
  return label[Math.max(rank[local] ?? 0, rank[idxAlert] ?? 0)];
}

/**
 * `shomra mcp serve` — Shomra AS an MCP server (stdio JSON-RPC 2.0). Point any
 * MCP-capable agent (Claude Code, Cursor, Cline, ChatGPT desktop, …) at it and
 * the LLM can call Shomra's checks as native tools in its own loop: after it
 * edits files it can `shomra_check` / `shomra_scan_models`, then `shomra_fix`.
 * Each tool is a thin bridge to the corresponding CLI verb with `--json`, so it
 * reuses the exact same engine as the CLI and editor — one engine, another face.
 */
async function cmdMcpServe(flags) {
  const { createInterface } = await import('node:readline');
  const { execFileSync } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const SELF = fileURLToPath(import.meta.url);
  const cwd = flags.path ? path.resolve(String(flags.path)) : process.cwd();

  const send = (msg) => process.stdout.write(JSON.stringify(msg) + '\n');
  const ok = (id, result) => send({ jsonrpc: '2.0', id, result });
  const fail = (id, code, message) => send({ jsonrpc: '2.0', id, error: { code, message } });

  // Run a shomra subcommand in a child process and return its --json output. Our
  // verbs still print JSON on a non-zero (findings-found) exit, so read stdout in
  // both the success and error branches.
  const runJson = (args) => {
    const run = () => execFileSync(process.execPath, [SELF, ...args, '--json'], { encoding: 'utf8', cwd, maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
    let out;
    try { out = run(); } catch (e) { out = e.stdout ? String(e.stdout) : ''; if (!out) return { text: String(e.stderr || e.message || 'command failed') }; }
    try { return { data: JSON.parse(out) }; } catch { return { text: out }; }
  };

  const TOOLS = [
    { name: 'shomra_check', description: 'Gate every AI artifact (MCP configs, skills, slash commands, hooks, rules files) under a path for security issues — local-first, no network needed. Returns findings with file, line, severity and verdict. Run this after editing AI artifacts.', inputSchema: { type: 'object', properties: { path: { type: 'string', description: 'File or directory to check (default: workspace root).' } } } },
    { name: 'shomra_scan_models', description: 'Detect the AI models the code loads (from_pretrained, hf_hub_download, SentenceTransformer, …) and look each up in the Shomra Model Index for known vulnerabilities. Returns each model\'s verdict, findings, and a safe-loading fix plan (kwargs to add to the load call). Run this after adding or changing model-loading code.', inputSchema: { type: 'object', properties: { path: { type: 'string', description: 'File or directory to scan (default: workspace root).' } } } },
    { name: 'shomra_fix', description: 'Generate a minimal security fix for one AI artifact. Returns the fixed content; set apply=true to write it to disk in place.', inputSchema: { type: 'object', properties: { file: { type: 'string', description: 'Path to the artifact to fix.' }, apply: { type: 'boolean', description: 'Write the fix to disk (default: false — return it only).' } }, required: ['file'] } },
    { name: 'shomra_explain', description: 'Explain the findings in one AI artifact: why each matters, a one-line exploit, and an honest false-positive read.', inputSchema: { type: 'object', properties: { file: { type: 'string', description: 'Path to the artifact to explain.' } }, required: ['file'] } },
  ];

  const callTool = (name, args) => {
    const a = args || {};
    if (name === 'shomra_check') return runJson(['check', a.path ? String(a.path) : '.']);
    if (name === 'shomra_scan_models') return runJson(['models', a.path ? String(a.path) : '.']);
    if (name === 'shomra_fix') return runJson(['fix', String(a.file || ''), ...(a.apply ? ['--apply'] : [])]);
    if (name === 'shomra_explain') return runJson(['why', String(a.file || '')]);
    return { text: `Unknown tool: ${name}`, isError: true };
  };

  const rl = createInterface({ input: process.stdin });
  rl.on('line', (line) => {
    const s = line.trim();
    if (!s) return;
    let msg;
    try { msg = JSON.parse(s); } catch { return; }
    const { id, method, params } = msg;
    try {
      if (method === 'initialize') return ok(id, { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'shomra', version: VERSION } });
      if (method === 'ping') return ok(id, {});
      if (method === 'tools/list') return ok(id, { tools: TOOLS });
      if (method === 'tools/call') {
        const res = callTool(params && params.name, params && params.arguments);
        const text = res.data !== undefined ? JSON.stringify(res.data, null, 2) : String(res.text != null ? res.text : '');
        return ok(id, { content: [{ type: 'text', text }], isError: !!res.isError });
      }
      if (typeof method === 'string' && method.startsWith('notifications/')) return; // no reply to notifications
      if (id !== undefined) return fail(id, -32601, `Method not found: ${method}`);
    } catch (e) {
      if (id !== undefined) return fail(id, -32603, String((e && e.message) || e));
    }
  });
  await new Promise((resolve) => rl.on('close', resolve));
}

async function cmdMcp(flags, positional) {
  const sub = String(positional[0] || '').toLowerCase();

  // `shomra mcp serve` — expose Shomra AS an MCP server so any LLM/coding agent
  // can call its checks as native tools (check / scan_models / fix / explain).
  if (sub === 'serve') return cmdMcpServe(flags);

  const configFile = path.resolve(flags.config ? String(flags.config) : '.mcp.json');

  if (sub === 'list') {
    const cfg = fs.existsSync(configFile) ? (() => { try { return JSON.parse(fs.readFileSync(configFile, 'utf8')); } catch { return {}; } })() : {};
    const servers = cfg.mcpServers || cfg.servers || {};
    const names = Object.keys(servers);
    if (flags.json) { console.log(JSON.stringify({ config: configFile, servers }, null, 2)); return; }
    console.log(bold(cyan('\n  MCP servers')) + dim(` — ${path.relative(process.cwd(), configFile).split(path.sep).join('/')}`));
    if (!names.length) console.log(dim('  (none)\n'));
    else { for (const n of names) console.log(`  ${green('●')} ${bold(n)} ${dim(servers[n].url || [servers[n].command, ...(servers[n].args || [])].filter(Boolean).join(' '))}`); console.log(''); }
    return;
  }

  if (sub !== 'add') {
    console.error(red('✗') + ` Usage: ${bold('shomra mcp add <name> <command…> | --url <url>')} ${dim('|')} ${bold('shomra mcp list')}`);
    process.exit(1);
  }

  const name = positional[1];
  if (!name) { console.error(red('✗') + ` Usage: ${bold('shomra mcp add <name> <command…>')}`); process.exit(1); }
  const server = {};
  if (flags.url) server.url = String(flags.url);
  const cmdTokens = flags.command ? String(flags.command).split(/\s+/) : positional.slice(2);
  if (cmdTokens.length) { server.command = cmdTokens[0]; if (cmdTokens.length > 1) server.args = cmdTokens.slice(1); }
  if (flags.env) server.env = parseEnvKV(flags.env);
  if (!server.url && !server.command) { console.error(red('✗') + ' Provide a launch command or --url.'); process.exit(1); }

  // Vet the candidate BEFORE writing it anywhere: (1) local heuristics, then
  // (2) the platform's pre-scanned MCP Security Index (GET /catalog/lookup) so a
  // server already scanned in the sandbox contributes its real findings without
  // running Docker here. The index is best-effort — offline/unknown just falls
  // back to the local verdict. Skip the network with --no-index.
  const candidate = JSON.stringify({ mcpServers: { [name]: server } }, null, 2);
  const g = localGate(candidate, { kind: 'mcp', path: '.mcp.json' });

  let index = null;
  if (!flags['no-index']) {
    try {
      const { url } = resolveSettings(loadConfig());
      index = await mcpLookup(url, mcpLookupId(server, name));
    } catch (e) {
      index = { error: e.message };
    }
  }
  const idxAlert = mcpIndexAlert(index);
  const verdict = worstMcpVerdict(g.verdict, idxAlert);

  if (!flags.json) {
    console.log(bold(cyan(`\n  Vetting MCP server "${name}"…`)));
    for (const f of g.findings.slice(0, 6)) console.log(`    ${SEV_COLOR[f.severity](String(f.severity).padEnd(8))} ${f.title} ${dim('(local)')}`);
    if (index && index.found && index.scanned) {
      const vc = index.verdict === 'FAIL' ? red : index.verdict === 'REVIEW' ? yellow : green;
      console.log(dim(`    ── MCP Security Index: `) + bold(index.slug) + dim(` · verdict `) + vc(String(index.verdict)) + dim(` · risk ${index.riskScore} ──`));
      for (const f of (index.findings || []).slice(0, 6)) console.log(`    ${(SEV_COLOR[f.severity] || dim)(String(f.severity).padEnd(8))} ${f.title} ${dim('(index)')}`);
      printAlternatives(index.alternatives, 'mcp', '    ');
    } else if (index && index.found && !index.scanned) {
      console.log(dim(`    MCP Security Index: found "${index.slug}" but it hasn't been scanned yet.`));
    } else if (index && index.error) {
      console.log(dim(`    MCP Security Index: unavailable (${index.error}) — using local checks only.`));
    } else if (index) {
      console.log(dim(`    MCP Security Index: not indexed — using local checks only.`));
    }
  }
  if (verdict === 'BLOCK' && !flags.force) {
    if (flags.json) console.log(JSON.stringify({ installed: false, verdict, local: g.verdict, index, findings: g.findings }, null, 2));
    else console.log(`\n  ${red('✗ Blocked — not installed.')} ${dim('Review the findings, or override with')} ${bold('--force')}${dim('.')}\n`);
    process.exitCode = 1;
    return;
  }

  // Merge into the target config.
  let cfg = {};
  if (fs.existsSync(configFile)) { try { cfg = JSON.parse(fs.readFileSync(configFile, 'utf8')); } catch { console.error(red('✗') + ` ${configFile} is not valid JSON.`); process.exit(1); } }
  cfg.mcpServers = cfg.mcpServers || {};
  const existed = !!cfg.mcpServers[name];
  cfg.mcpServers[name] = server;
  fs.mkdirSync(path.dirname(configFile), { recursive: true });
  fs.writeFileSync(configFile, JSON.stringify(cfg, null, 2) + '\n');

  const rel = path.relative(process.cwd(), configFile).split(path.sep).join('/');
  if (flags.json) { console.log(JSON.stringify({ installed: true, name, verdict, local: g.verdict, index, config: rel, updated: existed }, null, 2)); return; }
  const note = verdict === 'FLAG' ? yellow('  (flagged — review the findings above)') : verdict === 'BLOCK' ? red('  (forced past a BLOCK)') : green('  ✓ clean');
  console.log(`\n  ${green(existed ? '✓ Updated' : '✓ Added')} MCP server ${bold(name)} ${dim('→ ' + rel)}${note}\n`);
}

// ── shomra secrets: did I leak a key — now, or ever? ─────────────────────────
//
//   shomra secrets [dir] [--history] [--depth N] [--json]
//
// Scans the working tree for live credentials, and with --history walks git
// history too — a key deleted from HEAD but still reachable in an old commit is
// still compromised and must be rotated. Uses the same SECRET_PATTERNS as the
// gate. Nothing is sent anywhere; matched values are redacted in the output.
function redactSecret(s) {
  const t = String(s).trim();
  return t.length <= 8 ? t[0] + '••••' : `${t.slice(0, 4)}…${t.slice(-2)}`;
}
function isGitRepo(root) {
  try { execSync('git rev-parse --is-inside-work-tree', { cwd: root, stdio: ['ignore', 'pipe', 'ignore'] }); return true; }
  catch { return false; }
}
// Walk the working tree for text files (skipping .git / vendored dirs), so an
// UNTRACKED .env — the likeliest place a live secret sits — is scanned too.
function walkFiles(root, cap = 8000) {
  const found = [];
  const stack = [root];
  while (stack.length && found.length < cap) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const ent of entries) {
      if (ent.isDirectory()) { if (!SKIP_DIRS.has(ent.name) && ent.name !== '.git') stack.push(path.join(dir, ent.name)); continue; }
      found.push(path.relative(root, path.join(dir, ent.name)).split(path.sep).join('/'));
      if (found.length >= cap) break;
    }
  }
  return found;
}
// Stream git history, flagging secret-shaped tokens in ADDED lines. Bounded by depth.
function scanGitHistory(root, depth) {
  let out;
  try { out = execSync(`git log --all -p -n ${depth} --no-color --format="commit %H %an %ad"`, { cwd: root, stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 128 * 1024 * 1024 }).toString(); }
  catch { return null; }
  const hits = [];
  const seen = new Set();
  let commit = '', file = '';
  for (const line of out.split(/\r?\n/)) {
    if (line.startsWith('commit ')) { commit = line.slice(7, 19); continue; }
    if (line.startsWith('+++ b/')) { file = line.slice(6); continue; }
    if (line[0] !== '+' || line.startsWith('+++')) continue;
    const added = line.slice(1);
    for (const { name, re } of SECRET_PATTERNS) {
      const m = added.match(re);
      if (!m) continue;
      const key = `${commit}:${file}:${name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push({ where: 'history', commit, file, secret: name, sample: redactSecret(m[0]) });
    }
  }
  return hits;
}
function cmdSecrets(flags, positional) {
  const root = path.resolve(positional[0] || '.');
  const hits = [];
  const isGit = isGitRepo(root);
  for (const rel of walkFiles(root)) {
    let content;
    try {
      const full = path.join(root, rel);
      if (fs.statSync(full).size > MAX_ARTIFACT_BYTES) continue;
      content = fs.readFileSync(full, 'utf8');
    } catch { continue; }
    if (content.includes('\0')) continue; // skip binary
    for (const f of localScan(content, { categories: ['secret'] }).findings) {
      hits.push({ where: 'working-tree', file: rel, line: f.line, secret: f.label.replace(/^Live credential:\s*/, '') });
    }
  }
  let history = null;
  if (flags.history) {
    history = scanGitHistory(root, clampInt(flags.depth, 300, 1, 5000));
    if (history) hits.push(...history);
  }

  if (flags.json) { console.log(JSON.stringify({ workingTree: hits.filter((h) => h.where === 'working-tree').length, history: history ? history.length : null, hits }, null, 2)); return; }

  console.log(bold(cyan('\n  Shomra secrets')) + dim(` — ${path.relative(process.cwd(), root).split(path.sep).join('/') || '.'}${flags.history ? ' · working tree + git history' : ' · working tree'}`));
  if (!isGit) console.log(dim('  (not a git repo — working tree only; --history unavailable)'));
  else if (!flags.history) console.log(dim('  Tip: add ') + bold('--history') + dim(' to also scan past commits (a leaked key removed from HEAD is still live).'));
  const wt = hits.filter((h) => h.where === 'working-tree');
  const hi = hits.filter((h) => h.where === 'history');
  if (!hits.length) { console.log(green('\n  ✓ No secret-shaped values found.\n')); return; }
  if (wt.length) {
    console.log(red(`\n  ${wt.length} in the working tree:`));
    for (const h of wt.slice(0, 25)) console.log(`    ${red('●')} ${bold(h.file)}${h.line ? dim(':' + h.line) : ''} ${dim(h.secret)}`);
  }
  if (hi.length) {
    console.log(yellow(`\n  ${hi.length} in git history ${dim('(rotate — still reachable):')}`));
    for (const h of hi.slice(0, 25)) console.log(`    ${yellow('●')} ${dim(h.commit)} ${bold(h.file)} ${dim(h.secret + ' ' + (h.sample || ''))}`);
  }
  console.log(dim(`\n  Rotate every matched credential now. A committed secret is compromised even after you delete it — history keeps it.\n`));
  process.exitCode = 1;
}

// ── shomra models: which models does my code load — and are they safe? ───────
//
//   shomra models [dir] [--strict] [--json] [--dry-run]
//
// Scans source for the AI models the code loads (from_pretrained / SentenceTransformer
// / hf_hub_download / huggingface.co URLs / torch.hub.load / ollama), then looks each
// one up in the platform's Model Security Index (GET /models/lookup) and ALERTS on
// known vulnerabilities. You can't scan a model's weights from source — but the
// platform already scraped + scanned the popular ones, so a reference is enough.
// Pinned revisions (revision=) are looked up by exact commit sha. `--dry-run` shows
// what it detected + the lookup URLs without calling the API.
// On-machine cache of index verdicts (~/.shomra/model-cache.json) so the model
// check is LOCAL-FIRST: after the first sight a known-vulnerable model resolves
// with no network — offline, and unaffected by a slow/down/flapping backend.
// Only positive hits (found) are cached (misses re-check when online); a stale
// hit is still served when the backend is unreachable. SHOMRA_MODEL_CACHE=0 off.
const MODEL_CACHE_FILE = path.join(CONFIG_DIR, 'model-cache.json');
function modelCacheOff() { return process.env.SHOMRA_MODEL_CACHE === '0' || String(process.env.SHOMRA_MODEL_CACHE).toLowerCase() === 'false'; }
function loadModelCache() { try { return JSON.parse(fs.readFileSync(MODEL_CACHE_FILE, 'utf8')) || {}; } catch { return {}; } }
function saveModelCache(c) { try { fs.mkdirSync(CONFIG_DIR, { recursive: true }); fs.writeFileSync(MODEL_CACHE_FILE, JSON.stringify(c)); } catch { /* cache is best-effort */ } }

async function modelLookup(url, id, sha) {
  const key = `${id}@${sha || 'latest'}`;
  const ttl = clampInt(process.env.SHOMRA_MODEL_CACHE_TTL_MS, 7 * 24 * 3600 * 1000, 0, 365 * 24 * 3600 * 1000);
  const cache = modelCacheOff() ? {} : loadModelCache();
  const hit = cache[key];
  // Fresh cache hit → fully local, no network (works offline, ignores the breaker).
  if (hit && hit.cachedAt && Date.now() - hit.cachedAt < ttl) return { ...hit.data, cached: true };
  // No backend configured → the Model Index is enrichment only. Serve a cached
  // hit if we have one, else signal "not looked up" (callers treat it as offline).
  if (!url) {
    if (hit && hit.data) return { ...hit.data, cached: true, stale: true };
    throw new Error('model index not configured (set SHOMRA_URL to enrich)');
  }
  // Backend known-down (breaker open) → serve a stale hit rather than stalling.
  if (breakerOpen()) {
    if (hit && hit.data) return { ...hit.data, cached: true, stale: true };
    throw new Error('backend unavailable (circuit open)');
  }

  const q = `id=${encodeURIComponent(id)}${sha ? `&sha=${encodeURIComponent(sha)}` : ''}`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), clampInt(process.env.SHOMRA_API_TIMEOUT_MS, 15000, 1000, 60000));
  try {
    const res = await fetch(`${url}/models/lookup?${q}`, { signal: ctrl.signal, headers: { Accept: 'application/json', 'User-Agent': 'shomra-agent' } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    breakerReset();
    if (!modelCacheOff() && data && data.found) { cache[key] = { cachedAt: Date.now(), data }; saveModelCache(cache); }
    return data;
  } catch (e) {
    breakerTrip();
    if (hit && hit.data) return { ...hit.data, cached: true, stale: true }; // stale beats nothing
    throw e;
  } finally { clearTimeout(timer); }
}
const MODEL_SEV_RANK = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };

// Print the platform's "use this instead" suggestions for a flagged model / MCP
// server — the safer, lower-risk peers in the same category the index folds into
// a lookup. Deterministic, no AI. `kind` picks the id + URL fields to show.
function printAlternatives(alts, kind, indent = '      ') {
  if (!Array.isArray(alts) || !alts.length) return;
  console.log(`${indent}${green('↳ safer alternatives')} ${dim('(same category, lower risk):')}`);
  for (const a of alts.slice(0, 5)) {
    const id = kind === 'model' ? a.modelId : (a.packageName || a.name);
    const url = kind === 'model' ? a.url : (a.repoUrl || a.homepage || '');
    const vc = a.verdict === 'FAIL' ? red : a.verdict === 'REVIEW' ? yellow : green;
    const label = id && id !== a.name ? `${bold(a.name)} ${dim('(' + id + ')')}` : bold(a.name);
    console.log(`${indent}  ${green('•')} ${label}  ${vc(String(a.verdict || '—'))} ${dim('risk ' + (a.riskScore ?? '?') + '/100')}${url ? dim(' · ' + url) : ''}`);
  }
}

// Turn a flagged HF model's findings into the safe-loading kwargs to add to its
// `from_pretrained(...)` call. Deterministic — no AI. Each kwarg carries the
// reason it's recommended so the editor QuickPick / agent can explain the choice.
function modelFixPlan(findings, sha) {
  const text = (findings || []).map((f) => `${f.title || ''} ${f.description || ''} ${f.class || ''} ${f.surface || ''} ${f.remediation || ''}`).join(' ').toLowerCase();
  const kwargs = [];
  if (/pickle|\.bin\b|hdf5|\.h5\b|keras|serial|safetensors/.test(text)) {
    kwargs.push({ name: 'use_safetensors', value: 'True', reason: 'Load safetensors instead of pickle/HDF5 weights, which can execute code the moment they load.' });
  }
  // Only for findings that are actually about the repo shipping executable code
  // (not generic "pickle executes arbitrary code" prose, which safetensors fixes).
  if (/trust_remote_code|auto_map|remote code|custom (python )?code|modeling_[\w.]+\.py/.test(text)) {
    kwargs.push({ name: 'trust_remote_code', value: 'False', reason: "Never run the model repo's own Python during load." });
  }
  if (sha) {
    kwargs.push({ name: 'revision', value: JSON.stringify(String(sha).slice(0, 40)), reason: 'Pin to the exact revision Shomra reviewed instead of a mutable branch (supply-chain).' });
  }
  return kwargs.length ? { kwargs } : null;
}

async function cmdModels(flags, positional) {
  const cfg = loadConfig();
  const { url } = resolveSettings(cfg);
  const target = path.resolve(positional[0] || flags.path || '.');
  const dryRun = !!flags['dry-run'];

  // Accept either a directory (walk it) or a single file. The editor extension
  // scans just the file you saved, so `shomra models <file>` must work as well.
  let root = target;
  let entries;
  try {
    const st = fs.statSync(target);
    if (st.isFile()) { root = path.dirname(target); entries = [path.basename(target)]; }
    else entries = walkFiles(root);
  } catch { entries = []; }

  // 1. Detect model references across the repo's source, deduped by (id, sha).
  const refs = new Map(); // key → { id, sha, source, locations: [{file,line,via}] }
  for (const rel of entries) {
    if (!isModelRefScannable(rel)) continue;
    let content;
    try { const full = path.join(root, rel); if (fs.statSync(full).size > MAX_ARTIFACT_BYTES) continue; content = fs.readFileSync(full, 'utf8'); } catch { continue; }
    if (content.includes('\0')) continue;
    for (const r of scanModelRefs(content, rel)) {
      const key = `${r.source}:${r.id}:${r.revision || ''}`;
      if (!refs.has(key)) refs.set(key, { id: r.id, sha: r.revision || null, source: r.source, locations: [] });
      refs.get(key).locations.push({ file: r.file, line: r.line, via: r.via });
    }
  }
  const unique = [...refs.values()];

  if (!unique.length) {
    if (flags.json) console.log(JSON.stringify({ detected: 0, models: [] }, null, 2));
    else console.log(green('\n  ✓ No AI model references found in the code.') + dim(` (looked under ${path.relative(process.cwd(), root).split(path.sep).join('/') || '.'})`) + '\n');
    return;
  }

  if (dryRun) {
    if (flags.json) { console.log(JSON.stringify({ detected: unique.length, models: unique.map((u) => ({ id: u.id, sha: u.sha, source: u.source, lookup: `${url}/models/lookup?id=${encodeURIComponent(u.id)}${u.sha ? '&sha=' + u.sha : ''}`, locations: u.locations })) }, null, 2)); return; }
    console.log(bold(cyan('\n  Shomra models')) + dim(` — ${unique.length} reference(s) detected (dry run — no lookup)`));
    for (const u of unique) console.log(`  ${gray('•')} ${bold(u.id)}${u.sha ? dim('@' + u.sha) : ''} ${dim('(' + u.source + ')')} ${dim('→ ' + url + '/models/lookup?id=' + u.id)}`);
    console.log('');
    return;
  }

  // 2. Look each up in the Model Security Index (bounded-parallel).
  const looked = new Array(unique.length).fill(null);
  let apiDown = false;
  const conc = clampInt(process.env.SHOMRA_GATE_CONCURRENCY, 6, 1, 16);
  let next = 0;
  const worker = async () => {
    while (true) {
      const i = next++;
      if (i >= unique.length || apiDown) return;
      // ollama-runtime ids (no org/name) aren't in the HF-oriented index; skip lookup.
      if (unique[i].source === 'ollama') { looked[i] = { found: false, local: true }; continue; }
      try { looked[i] = await modelLookup(url, unique[i].id, unique[i].sha); }
      catch (e) { apiDown = true; looked[i] = { error: e.message }; }
    }
  };
  await Promise.all(Array.from({ length: Math.min(conc, unique.length) }, worker));

  // 3. Classify + alert.
  const models = unique.map((u, i) => {
    const r = looked[i] || {};
    const findings = r.findings || [];
    const worst = findings.reduce((m, f) => Math.max(m, MODEL_SEV_RANK[f.severity] || 0), 0);
    const alert = r.found && (r.verdict === 'FAIL' || worst >= MODEL_SEV_RANK.CRITICAL) ? 'BLOCK'
      : r.found && (r.verdict === 'REVIEW' || worst >= MODEL_SEV_RANK.HIGH) ? 'FLAG'
      : 'OK';
    // A deterministic remediation plan for a flagged HF load: the safe-loading
    // kwargs to add to the `from_pretrained(...)` call, chosen from what the model
    // was flagged for. The editor turns this into a "Harden this model load"
    // quick-fix; the MCP `shomra_fix` tool returns it for an agent to apply.
    const fix = r.found && alert !== 'OK' && u.source === 'hf' ? modelFixPlan(findings, r.sha) : null;
    // Safer, lower-risk models in the same category the index folded into the
    // lookup — the "use this instead" fix for a vulnerable model reference.
    const alternatives = alert !== 'OK' ? (r.alternatives || []) : [];
    return { ...u, found: !!r.found, verdict: r.verdict || null, riskScore: r.riskScore ?? null, scannedSha: r.sha || null, findingCount: findings.length, findings, alert, fix, alternatives, error: r.error, notIndexed: !r.found && !r.error };
  });
  const blocked = models.filter((m) => m.alert === 'BLOCK').length;
  const flagged = models.filter((m) => m.alert === 'FLAG').length;

  if (flags.json) {
    console.log(JSON.stringify({ detected: models.length, blocked, flagged, apiDown, url, models }, null, 2));
  } else {
    console.log(bold(cyan('\n  Shomra models')) + dim(` — ${models.length} model reference(s)${url ? ` · index at ${url}` : ' · local detection only'}`));
    if (apiDown) console.log(`  ${yellow('⚠')} ${dim(url ? 'Model index unreachable — could not fetch vulnerability info.' : 'Model index not configured — set SHOMRA_URL to check models against the Shomra Model Index.')}`);
    for (const m of models) {
      const mark = m.alert === 'BLOCK' ? red('●') : m.alert === 'FLAG' ? yellow('●') : m.notIndexed ? gray('○') : green('●');
      const status = m.error ? yellow('lookup failed')
        : m.notIndexed ? dim(m.source === 'ollama' ? 'local runtime — not in the index' : 'not in the index yet')
        : `${m.verdict === 'FAIL' ? red(m.verdict) : m.verdict === 'REVIEW' ? yellow(m.verdict) : green(m.verdict)} ${dim('risk ' + m.riskScore + ' · ' + m.findingCount + ' vuln(s)')}`;
      console.log(`  ${mark} ${bold(m.id)}${m.sha ? dim('@' + String(m.sha).slice(0, 12)) : ''} ${dim('(' + m.source + ')')}  ${status}`);
      console.log(`      ${dim('used in ' + m.locations.slice(0, 3).map((l) => l.file + ':' + l.line).join(', ') + (m.locations.length > 3 ? ` (+${m.locations.length - 3})` : ''))}`);
      for (const f of m.findings.slice(0, 3)) console.log(`      ${(SEV_COLOR[f.severity] || dim)(String(f.severity).padEnd(8))} ${f.title}`);
      printAlternatives(m.alternatives, 'model');
      if (m.notIndexed && m.source !== 'ollama') console.log(`      ${dim('→ scan it now:')} ${bold('shomra model-scan ' + m.id)}`);
    }
    console.log(
      '\n  ' + (blocked ? red(`✗ ${blocked} vulnerable`) + dim(` · ${flagged} to review`) : flagged ? yellow(`⚠ ${flagged} to review`) : green('✓ No known-vulnerable models')) + '\n',
    );
  }

  if (blocked) process.exitCode = 1;
  else if (flagged && flags.strict) process.exitCode = 2;
}

function cmdHelp() {
  console.log(`
${bold(cyan('Shomra'))} ${dim('— AI security agent v' + VERSION)}

${bold('USAGE')}
  shomra <command> [options]

${bold('MODES')}  ${dim('— local-first: everything that can run on your machine does, with no account')}
  ${cyan('Local')}     ${dim('(no key)')}  check · gate · doctor · protect · secrets · models · new · mcp add
                        ${dim('Fully on-machine. Nothing leaves your machine. Your lead-in — no signup.')}
  ${green('Enrolled')}  ${dim('(shm_live_)')} adds org policy, AI ${bold('fix')}/${bold('why')}, deep scans (zip/model/memory) & the dashboard
  ${green('CI')}        ${dim('(shm_ci_)')}   scoped, revocable pipeline key for ${bold('pr')} / ${bold('check')} in CI
  ${dim('Enroll with')} ${bold('shomra init --key shm_…')}${dim('; generate keys in the platform → Settings → API Keys.')}

${bold('COMMANDS')}
  ${dim('Daily — the verbs you live in')}
  ${cyan('check')}         ${bold('Is my repo safe?')} Gate every AI artifact  ${dim('[dir] [--staged|--changed] [--fix] [--strict] [--json]')}
  ${cyan('fix')}           Remediate an artifact in place (AI)    ${dim('<file> [--apply] [--kind …] [--json]')}
  ${cyan('why')}           Explain a finding + false-positive read ${dim('<file> [--kind …] [--json]')}
  ${cyan('gate')}          Vet ONE AI artifact before install     ${dim('<file> [--kind …] [--strict] [--json]  ·  --all for a whole repo (CI)')}
  ${cyan('scan')}          Discover AI tooling on this machine    ${dim('[--report] [--json] [--path <dir>]')}
  ${cyan('status')}        Show config, enrollment + firewall health

  ${dim('Setup — run once per machine / repo')}
  ${cyan('init')}          Configure + enroll this machine       ${dim('--key shm_live_… [--url <backend>]')}
  ${cyan('protect')}       Wire the runtime firewall for every coding agent ${dim('[--local] [--force]')}
  ${cyan('install-hook')}  Wire the runtime firewall into ONE agent ${dim('[--agent claude|cursor|windsurf|gemini|codex|copilot|cline|aider|all] [--global]')}
  ${cyan('install-precommit')} Gate staged AI artifacts on git commit ${dim('[dir] [--force]')}
  ${cyan('doctor')}        ${bold('Am I safe?')} Posture of this machine's AI setup ${dim('[--json]')}

  ${dim('CI & repo hygiene')}
  ${cyan('pr')}            Review a PR — inline findings on the diff ${dim('(CI) [--init] [--strict] [--dry-run]')}
  ${cyan('baseline')}      Accept current findings; only NEW ones fail ${dim('[dir]')}
  ${cyan('secrets')}       Scan working tree + git history for leaked keys ${dim('[dir] [--history] [--depth N]')}
  ${cyan('models')}        Find models the code loads + look up known vulns ${dim('[dir] [--strict] [--dry-run]')}

  ${dim('Build safely')}
  ${cyan('new')}           Scaffold a secure-by-default artifact  ${dim('skill|command|subagent|agent-card|mcp|rules [name]')}
  ${cyan('mcp add')}       Vet an MCP server, then add it to a config ${dim('<name> <command…>|--url <url> [--config <f>] [--force]')}
  ${cyan('mcp serve')}     Run Shomra AS an MCP server so agents call its checks ${dim('(check/scan_models/fix/explain tools)')}

  ${dim('Governance & advanced')}  ${dim('→')} ${bold('shomra admin')} ${dim('for the full list')}
  ${cyan('admin')}         Deep scans, red-team, hardening, agent identity, LLM proxy
                ${dim('scan-zip · model-scan · memory-scan · redteam · campaign · harden · agent-identity · llm-proxy')}

  ${dim('(internal hook handlers, invoked by install-hook — not run by hand: tool-guard, result-guard)')}

${bold('GATE')}
  Checks an MCP config / Skill / slash command / hook / rules file BEFORE it
  lands on the machine. Exit 0 = allowed, 1 = blocked (2 = flagged with --strict)
  — wire it into pre-commit or CI. Nothing is executed; analysis is static.

  ${bold('Works offline.')} Real static analysis (dangerous shell, prompt injection,
  secrets, exfil sinks, over-permissioned tool grants, install-lure prose) runs
  ON-MACHINE, so ${bold('gate')} returns a genuine verdict with no backend and no key.
  When enrolled + reachable, the backend layers your ORG POLICY + governance on
  top. If the backend is down it falls back to the local verdict (and says so);
  ${bold('--strict')} instead fails closed (exit 1) because org policy couldn't be verified.

  ${bold('--all')} walks a repo/dir and gates every AI artifact at once — drop it in
  a CI job to fail the build on risky artifacts. CI environment (provider, repo,
  branch, commit) is auto-detected and recorded for local-vs-CI gate activity.

${bold('CHECK')}  ${dim('— the one command a developer runs')}
  ${bold('shomra check')} answers "is my repo safe?" in one shot: it finds every AI
  artifact in the tree (MCP configs, Skills, slash commands, hooks, rules files)
  and gates them together, ${bold('local-first')} — a real on-machine verdict with no
  backend or key; enrolling layers your org policy on top. It is ${bold('gate --all')}
  with dev ergonomics:
    ${dim('shomra check')}            every AI artifact under the repo
    ${dim('shomra check --staged')}   only what's git-staged  ${dim('(wire into pre-commit / on-save)')}
    ${dim('shomra check --changed')}  only what changed vs HEAD
    ${dim('shomra check --fix')}      gate, then remediate what isn't clean, in place
    ${dim('shomra check --json')}     machine-readable — what an IDE extension calls
    ${dim('shomra check --sarif')}    SARIF 2.1.0 — upload for native GitHub/GitLab PR annotations
  Exit 0 = clean, 1 = blocked, 2 = flagged with --strict.

${bold('BASELINE & SUPPRESSION')}  ${dim('— adopt on a messy repo; silence a false positive')}
  ${bold('shomra baseline')} records the current findings as accepted (.shomra/baseline.json,
  line-independent) so only findings introduced AFTER it fail — commit it to share
  with the team. Silence individual findings three ways:
    ${dim('.shomraignore')}   a repo file: ${dim('path/glob')} (skip file) or ${dim('path/glob :: title-substring')}
    ${dim('inline comment')}  ${bold('// shomra-ignore')} / ${bold('# shomra-ignore')} on the finding's line or the one above
    ${dim('whole file')}      ${bold('shomra-ignore-file')} in the first lines (works in JSON too)
  Any suppression re-grades the artifact, so a fully-suppressed file drops to ALLOW.
  ${dim('--no-suppress')} ignores all of the above; ${dim('--no-baseline')} ignores just the baseline.

${bold('POLICY-AS-CODE')}  ${dim('— team gate rules, versioned in the repo')}
  ${bold('.shomra/policy.yml')} (or .json) sets your team's thresholds, reviewed in PRs:
    ${dim('block: high')}       min severity that BLOCKS   ${dim('(critical|high|medium|low|none)')}
    ${dim('flag:  medium')}     min severity that FLAGS
    ${dim('allow: ["IPv4 address"]')}  finding titles to always downgrade
  For a local verdict the repo policy fully re-grades; when the backend returned an
  org decision it can only make it STRICTER (worst-wins). ${dim('--no-policy')} skips it.

${bold('FIX')}  ${dim('— remediate without leaving your editor')}
  ${bold('shomra fix <file>')} generates a MINIMAL fix for whatever the gate flags in
  that artifact and shows it as a unified diff; ${bold('--apply')} writes it back to the
  local file. The fix is produced on the platform with your org's AI key (so no
  provider key sits on the dev machine) — enrollment is required. When the
  server has no AI configured it degrades to printing the deterministic
  remediation guidance to apply by hand. Nothing is committed or pushed; the
  edit lands in your working tree for you to review and commit.

${bold('WHY')}  ${dim('— decide if a finding is real')}
  ${bold('shomra why <file>')} is the developer shape of "investigate": for each finding
  it gives a plain-English why-it-matters, a one-line exploit scenario, and an
  honest true/false-positive read — the conclusion, not a tool-call timeline.
  AI-distilled when enrolled; offline it prints the on-machine findings and their
  fixes. Use it when the gate flags something you think is a false positive.

${bold('INSTALL-PRECOMMIT')}
  ${bold('shomra install-precommit')} writes a ${dim('.git/hooks/pre-commit')} that runs
  ${bold('check --staged')}, so a risky MCP config / skill / rules file is caught before
  it commits. A BLOCK stops the commit; flags warn but don't. Existing hooks are
  never clobbered (it tells you the one line to add, or ${bold('--force')} replaces with
  a backup). Override a single commit with ${bold('git commit --no-verify')}.

${bold('MODEL-SCAN')}
  Runs SAST over a public AI model's SOURCE — the custom .py files transformers
  imports under trust_remote_code and the config.json/tokenizer that bind them.
  Flags eval/exec/os.system/subprocess, pickle/torch.load deserialization,
  __reduce__ gadgets, network egress and auto_map (AutoModel/AutoTokenizer)
  usage, each with a rule id, file:line and code snippet. Weights are never
  downloaded and nothing is executed. Findings land in your Shomra dashboard.

${bold('MEMORY-SCAN')}
  Persistent agent memory (MEMORY.md, .claude/memory/…, mem0/letta stores) AND
  rules/instruction files (CLAUDE.md, AGENTS.md, .cursorrules, copilot-instructions,
  …) are re-fed to the model as trusted context every session — so a single
  poisoned entry (OWASP ASI06 / the MemoryTrap class) persists across sessions and
  reboots. Rules files are graded against an instruction baseline (standing
  directives are legitimate there; only hijack / conceal-from-user / staged-payload
  / exfil phrasing is poison), memory against a fact baseline. memory-scan reports
  each write (with provenance) so Shomra can track drift from an approved baseline
  and roll back a poisoned store. Once ${bold('install-hook')} is wired, the agent's own
  memory and rules-file writes are captured automatically. Analysis is static.

${bold('REDTEAM')}
  Replays a library of adversarial scenarios (goal hijack, indirect injection,
  system-prompt leak, data exfil, tool escalation, jailbreak, secret extraction,
  memory poisoning) against your OWN LLM Guard (in probe mode — never logged as a
  real attack) or model, scores a resilience %, and flags REGRESSIONS vs the last
  run. Authorized testing of your own stack; nothing is executed and no attack
  leaves the platform. Add ${bold('--evolve')} to turn on the evolutionary attacker: a
  population-based genetic search that breeds evasive variants (obfuscation,
  encoding, wrapping, splitting) against any scenario the fixed set can't crack,
  learning what beats YOUR guard and opening with it next time. Works with AI on
  or off. In CI, gate the pipeline with ${bold('--min <resilience>')} and/or
  ${bold('--fail-on-regression')} (exit 2 fails the build). Run it on a schedule so a model
  or policy change can't silently weaken a defense.

${bold('HARDEN')}
  The self-hardening flywheel — turns a red-team breach into a defense. Runs a
  red-team (or reuses one with ${bold('--run <id>')}), asks Shomra to propose high-precision
  detection signatures for whatever got through, and VERIFIES each against a
  benign corpus: a candidate must catch the attack AND fire on zero legitimate
  messages, so the guard can only ever get tighter. With ${bold('--apply')} the survivors
  go live as a signature pack — no redeploy — and a confirmation re-run proves
  the resilience lift. Without AI configured it still works, mining signatures
  deterministically from the breaching prompts. Pair it with ${bold('redteam')} in CI.

${bold('AGENT IDENTITY')}
  Give each non-human agent a first-class identity with a least-privilege
  capability policy — which providers/models it may call, which tools / MCP
  servers it may invoke, whether it may run shell. ${bold('agent-identity register')} mints
  its shm_agt_ credential; export ${bold('SHOMRA_AGENT')} so ${bold('llm-proxy')} and the runtime
  firewall present it, and every call is authorized against its policy at the two
  runtime chokepoints (identity axis) on top of content screening. Govern,
  approve break-glass requests, and revoke (a live kill-switch) in the dashboard
  → Agent Identities. Unknown agents are auto-discovered there for visibility.

${bold('LLM-PROXY')}
  Runs a local guard in front of your LLM providers. Point your SDK's base URL
  at it (OPENAI_BASE_URL / ANTHROPIC_BASE_URL, the Google GenAI base URL, or any
  OpenAI-compatible SDK's baseURL) — every prompt and completion is screened
  against your org's policies; violations are blocked with HTTP 403 and logged
  to the LLM Guard dashboard. Supported providers:
    ${dim(LLM_PROVIDERS.join(' · '))}
  openai + the OpenAI-compatible ones share the /<provider>/v1 path shape;
  anthropic and gemini use their own (/anthropic, /gemini).

${bold('RUNTIME FIREWALL (multi-agent)')}
  ${bold('shomra install-hook')} wires Shomra into a coding agent's own hook system so
  it screens both channels — the pre-tool-call hook BEFORE a shell command,
  artifact write (adding an MCP/skill/command/hook/rules file), or MCP call
  runs, and the post-tool-call hook that screens content (WebFetch/Read/MCP
  responses) coming BACK into the agent's context for prompt injection, exfil
  sinks, and hidden payloads before the model acts on them.

  Default target is Claude Code (unchanged for existing installs). Add
  ${bold('--agent <name>')} (comma-separated, or ${bold('all')}) to also wire in:
    ${dim('claude')} (Claude Code) · ${dim('cursor')} (Cursor) · ${dim('windsurf')} (Windsurf/Cascade) ·
    ${dim('gemini')} (Gemini CLI) · ${dim('codex')} (OpenAI Codex CLI) · ${dim('copilot')} (GitHub Copilot CLI)
  e.g. ${dim('shomra install-hook --agent cursor,windsurf')} or ${dim('shomra install-hook --agent all')}.
  Windsurf's post-hooks can flag/log but not withhold a result (vendor limit).

  Risky calls/results are blocked and every decision lands in Gate Activity,
  tagged with which agent triggered it.

  ${bold('Tiered enforcement (fast + unbreakable).')} The guard decides the dangerous
  majority ON-MACHINE with zero network — curl|sh, reverse shells, base64 RCE,
  live secrets, injection — so protection survives a slow, down, or blocked
  backend and adds no latency to ordinary calls. Only policy-relevant calls
  (artifact installs, MCP calls, agent-identity, network egress, or anything
  the local tier flags) escalate to the server for the full org-policy /
  identity / governance / flow engine, with a short timeout + a circuit breaker
  that skips a known-down backend. Fail-open by default (the local tier is still
  enforcing); SHOMRA_GUARD_STRICT=1 to also fail-closed on the server tier.

${bold('ENV')}
  SHOMRA_API_KEY              API key (overrides config)
  SHOMRA_URL                  Backend URL (overrides config)
  SHOMRA_API_TIMEOUT_MS=30000 Per-request backend timeout for scan/gate/report (never hangs)
  SHOMRA_AGENT                Agent-identity handle presented as x-shomra-agent (llm-proxy + firewall)
  SHOMRA_GUARD_STRICT=1       Fail-closed on the server tier if the backend is unreachable
  SHOMRA_GUARD_LOCAL=0        Disable the on-machine Tier-0 guard (route everything to the server)
  SHOMRA_GUARD_IGNORE=<globs> Comma-separated file globs the runtime guard treats as known-safe (never
                             withheld) — plus any .shomraignore in the working dir. For files with
                             benign patterns in source (detection code, fixtures, docs).
  SHOMRA_GUARD_ALWAYS_ESCALATE=1  Send every call to the server (full telemetry, higher overhead)
  SHOMRA_GUARD_TIMEOUT_MS=2000    Per-call server timeout budget (default 2000)
  SHOMRA_GUARD_BREAKER_MS=30000   Skip the server for this long after a failure (0 disables)
`);
}

// The full verb table — every handler normalized to a (flags, positional) thunk
// so both the top-level dispatcher and the `admin` namespace share one source of
// truth. Adding a verb here wires it into both automatically.
const COMMANDS = {
  init: (f) => cmdInit(f),
  scan: (f) => cmdScan(f),
  report: (f) => cmdScan({ ...f, report: true }),
  gate: (f, p) => cmdGate(f, p),
  check: (f, p) => cmdCheck(f, p),
  pr: (f, p) => cmdPr(f, p),
  baseline: (f, p) => cmdBaseline(f, p),
  fix: (f, p) => cmdFix(f, p),
  why: (f, p) => cmdWhy(f, p),
  'install-precommit': (f, p) => cmdInstallPrecommit(f, p),
  'scan-zip': (f, p) => cmdScanZip(f, p),
  'model-scan': (f, p) => cmdModelScan(f, p),
  models: (f, p) => cmdModels(f, p),
  'memory-scan': (f, p) => cmdMemoryScan(f, p),
  redteam: (f) => cmdRedteam(f),
  campaign: (f) => cmdCampaign(f),
  harden: (f) => cmdHarden(f),
  'agent-identity': (f, p) => cmdAgentIdentity(f, p),
  'agent-id': (f, p) => cmdAgentIdentity(f, p),
  'llm-proxy': (f) => cmdLlmProxy(f),
  'tool-guard': (f) => cmdToolGuard(f),
  'result-guard': (f) => cmdResultGuard(f),
  'install-hook': (f) => cmdInstallHook(f),
  protect: (f) => cmdProtect(f),
  doctor: (f) => cmdDoctor(f),
  new: (f, p) => cmdNew(f, p),
  mcp: (f, p) => cmdMcp(f, p),
  secrets: (f, p) => cmdSecrets(f, p),
  status: () => cmdStatus(),
};

// Governance / advanced verbs. They keep working at the top level (back-compat),
// but the help leads with the daily verbs and points here for the rest, so the
// front door reads as a handful of commands rather than thirty. `shomra admin`
// (no subcommand) lists them.
const ADMIN_VERBS = new Set([
  'scan-zip', 'model-scan', 'memory-scan',
  'redteam', 'campaign', 'harden',
  'agent-identity', 'agent-id', 'llm-proxy',
]);

async function main() {
  const [, , command, ...rest] = process.argv;
  const { flags, positional } = parseFlags(rest);

  if (command === 'help' || command === undefined || command === '--help' || command === '-h') {
    return cmdHelp();
  }

  // `shomra admin <verb> …` — the governance namespace.
  if (command === 'admin') {
    const sub = positional[0];
    if (!sub || sub === 'help' || flags.help) return cmdAdminHelp();
    const fn = COMMANDS[sub];
    if (!fn || !ADMIN_VERBS.has(sub)) {
      console.error(red(`Unknown admin command: ${sub ?? ''}`));
      cmdAdminHelp();
      process.exit(1);
    }
    return fn(flags, positional.slice(1));
  }

  const fn = COMMANDS[command];
  if (!fn) {
    console.error(red(`Unknown command: ${command}`));
    cmdHelp();
    process.exit(1);
  }
  return fn(flags, positional);
}

function cmdAdminHelp() {
  console.log(`
${bold(cyan('shomra admin'))} ${dim('— governance & advanced security operations')}

  ${dim('Deep scans (backend + key)')}
  ${cyan('scan-zip')}      Static-scan a workspace ZIP            ${dim('<file.zip> [--project <id>] [--json]')}
  ${cyan('model-scan')}    SAST-scan a public AI model            ${dim('<hf-url | owner/model | github-url> [--project <id>] [--json]')}
  ${cyan('memory-scan')}   Scan memory + rules files for poisoning ${dim('[path] [--scope …] [--writer …] [--json]')}

  ${dim('Offense & runtime identity')}
  ${cyan('redteam')}       Continuously red-team your guardrails  ${dim('[--target llm-guard|model] [--evolve] [--min 80] [--fail-on-regression] [--json]')}
  ${cyan('campaign')}      Autonomous multi-turn adversary run    ${dim('[--objectives exfil-canary,tool-abuse] [--turns 6] [--min 80] [--json]')}
  ${cyan('harden')}        Auto-fix what the red-team breached     ${dim('[--run <id>] [--target llm-guard|model] [--apply] [--json]')}
  ${cyan('agent-identity')} Register a non-human agent identity    ${dim('register --name "…" --type coding-agent [--json]')}
  ${cyan('llm-proxy')}     Guardrail live LLM traffic             ${dim('[--port 4141] [--project <id>] [--agent-id <handle>]')}

  ${dim('Each also runs as a bare top-level verb (e.g.')} ${dim(bold('shomra redteam'))}${dim(') for back-compat.')}
  ${dim('Full details for any command:')} ${bold('shomra help')}
`);
}

main().catch((e) => {
  console.error(red('✗ ' + e.message));
  process.exit(1);
});
