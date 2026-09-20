import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { agentHookFiles } from '../agents/hook-files.mjs';
import { PACKAGE_SPEC, SELF_PATH, shomraHookRe } from '../agents/hook-command.mjs';
import { KIND_LABEL, VENDOR_TOOLS, matcherCovers, missingTools } from '../agents/vendor-tools.mjs';
import { VERSION } from '../core/version.mjs';

/**
 *  WHAT A SETTINGS FILE ACTUALLY PUTS IN FRONT OF THE HOOK - read on the
 * machine, with no network.
 *
 * ⚠ AN INSTALLED HOOK IS NOT A COVERED ONE. The entry can be present, point at
 * the right binary and still name a matcher that leaves this vendor's shell tool
 * out, in which case every command the agent runs reaches nobody while the
 * settings file, the dashboard and `shomra status` all say "installed". That gap
 * is the one thing a server-side simulation cannot see, so it is stated as its
 * own state (POROUS) with the exact names and the command that widens them.
 */

const home = () => os.homedir();

export const STATE = { OK: 'ok', POROUS: 'porous', ABSENT: 'absent', STALE: 'stale' };

function expand(p) {
  if (p.startsWith('~/')) return path.join(home(), p.slice(2));
  if (p.startsWith('./')) return path.join(process.cwd(), p.slice(2));
  return p;
}

/** A vendor counts as present when its own config root exists - the hook may or may not be in it yet. */
export function vendorInstalled(vendor) {
  const v = VENDOR_TOOLS[vendor];
  if (!v) return false;
  if ((v.probes ?? []).some((p) => fs.existsSync(expand(p)))) return true;
  return agentHookFiles(vendor).some((f) => fs.existsSync(f));
}

export function installedVendors(keys = Object.keys(VENDOR_TOOLS)) {
  return keys.filter((k) => vendorInstalled(k));
}

function readJson(file) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * Every Shomra tool-guard entry in one settings file, in the vendor's own shape.
 * ⚠ `matcher: null` is not "no matcher" - for a flat-event vendor there is no
 * such field, and the EVENT is what decides whether the hook runs.
 */
export function hookEntries(vendor, file) {
  const cfg = readJson(file);
  if (!cfg) return [];
  const re = shomraHookRe('tool-guard');
  const out = [];
  const shape = VENDOR_TOOLS[vendor]?.settings?.shape;

  const grouped = (list, event) => {
    for (const g of Array.isArray(list) ? list : []) {
      for (const h of Array.isArray(g?.hooks) ? g.hooks : []) {
        const command = String(h?.command ?? '');
        if (re.test(command)) out.push({ event, matcher: typeof g.matcher === 'string' ? g.matcher : '', command });
      }
    }
  };
  const flat = (list, event) => {
    for (const h of Array.isArray(list) ? list : []) {
      const command = String(h?.command ?? '');
      if (re.test(command)) out.push({ event, matcher: null, command });
    }
  };

  if (shape === 'claude' || shape === 'gemini') grouped(cfg.hooks?.[VENDOR_TOOLS[vendor].event], VENDOR_TOOLS[vendor].event);
  else if (shape === 'codex') grouped(cfg[VENDOR_TOOLS[vendor].event], VENDOR_TOOLS[vendor].event);
  else if (shape === 'flat-events') for (const e of [...VENDOR_TOOLS[vendor].events, ...VENDOR_TOOLS[vendor].postEvents]) flat(cfg.hooks?.[e.name], e.name);
  else if (shape === 'copilot') for (const e of VENDOR_TOOLS[vendor].events) flat(cfg[e.name], e.name);
  return out;
}

/**
 * ⚠ A HOOK THAT NAMES A BINARY THAT IS NOT THERE IS NOT A HOOK. The agent logs a
 * spawn error nobody reads and runs the call. Checked here because only the
 * machine can: an absolute path from another checkout, or a pinned npm version
 * that is not the one running, both read as "installed" everywhere else.
 */
export function commandHealth(command) {
  const npm = /@shomra\/agent@([\w.\-]+)/.exec(command);
  if (npm) {
    return npm[1] === VERSION
      ? { ok: true, how: 'npm', detail: PACKAGE_SPEC }
      : { ok: true, stale: true, how: 'npm', detail: `pinned to @shomra/agent@${npm[1]}, this CLI is ${VERSION}` };
  }
  const named = [...command.matchAll(/"([^"]+shomra\.mjs)"|(\S+shomra\.mjs)/g)].map((m) => m[1] ?? m[2]).filter(Boolean);
  const target = named[0];
  if (!target) return { ok: true, how: 'npm', detail: 'resolved through the package manager' };
  if (!fs.existsSync(target)) return { ok: false, how: 'path', detail: `${target} does not exist on this machine - the agent's hook spawn fails and the call runs unscreened` };
  const same = path.resolve(target) === path.resolve(SELF_PATH);
  return same
    ? { ok: true, how: 'path', detail: target }
    : { ok: true, stale: true, how: 'path', detail: `${target} is a different install than the one running (${SELF_PATH})` };
}

function scopeOf(file) {
  return file.startsWith(home()) ? 'user' : 'project';
}

/**
 * The static reading for one vendor: is the hook there, does it point at a real
 * binary, and does what it names cover every tool this vendor uses for shell,
 * write, edit, patch and MCP.
 */
export function staticCheck(vendor) {
  const v = VENDOR_TOOLS[vendor];
  const files = agentHookFiles(vendor).filter((f) => fs.existsSync(f));
  const installs = files.flatMap((file) => hookEntries(vendor, file).map((e) => ({ ...e, file, scope: scopeOf(file) })));
  const fix = `shomra install-hook --agent ${vendor}`;

  if (!installs.length) {
    return {
      vendor,
      label: v.label,
      state: STATE.ABSENT,
      files,
      installs: [],
      missing: [],
      notes: [],
      fix,
      statement: `No Shomra tool-guard hook is installed for ${v.label} on this machine, so nothing screens what it runs.`,
    };
  }

  const notes = [];
  let stale = null;
  for (const i of installs) {
    const health = commandHealth(i.command);
    i.health = health;
    if (!health.ok) {
      return {
        vendor,
        label: v.label,
        state: STATE.STALE,
        files,
        installs,
        missing: [],
        notes,
        fix,
        statement: `${v.label}'s hook points at a binary that is not on this machine: ${health.detail}.`,
      };
    }
    if (health.stale) stale = health.detail;
  }

  /** Matcher-based vendors: every required name must be covered by SOME installed entry's matcher. */
  const missing = [];
  if (v.matcher !== null) {
    const matchers = installs.filter((i) => i.matcher !== null).map((i) => i.matcher);
    for (const t of missingTools(vendor, matchers.join('|'))) missing.push({ ...t, why: KIND_LABEL[t.kind] });
  }

  /** Flat-event vendors: the event IS the coverage. */
  const missingEvents = [];
  for (const e of v.events ?? []) {
    if (v.matcher !== null) continue;
    if (!installs.some((i) => i.event === e.name)) missingEvents.push({ name: e.name, kind: e.kind, why: KIND_LABEL[e.kind] });
  }
  /** Copilot wires one pre-event for every tool; its required names are screened, not matched. */
  if (v.matcher === null && v.settings.shape === 'copilot') missing.length = 0;

  for (const e of v.postEvents ?? []) if (e.note) notes.push(e.note);
  if (stale) notes.push(stale);

  const porous = missing.length > 0 || missingEvents.length > 0;
  return {
    vendor,
    label: v.label,
    state: porous ? STATE.POROUS : STATE.OK,
    files,
    installs,
    missing,
    missingEvents,
    notes,
    fix,
    statement: porous
      ? `${v.label}'s hook never sees ${[...missing.map((m) => m.name), ...missingEvents.map((m) => m.name)].join(', ')} - `
        + `${[...new Set([...missing, ...missingEvents].map((m) => m.why))].join(' and ')} run with nothing in front of them.`
      : `${v.label}'s hook covers every tool it uses for shell, writes, edits and MCP calls.`,
  };
}

/** ⚠ Reported so a machine that cannot reach the server is not read as a machine nothing refused. */
export function environmentChecks({ url, apiKey, strict, breakerOpen, subjectTypes }) {
  const rows = [];
  rows.push({
    id: 'server',
    ok: !!url && !!apiKey,
    label: 'Server and credentials',
    detail: url && apiKey ? `${url} · key ${String(apiKey).slice(0, 10)}…` : 'not configured - run `shomra init --key shm_… --url <backend>`; only the local tier runs',
  });
  rows.push({
    id: 'breaker',
    ok: !breakerOpen,
    label: 'Circuit breaker',
    detail: breakerOpen ? 'OPEN - the server tier is being skipped after an earlier failure' : 'closed',
  });
  rows.push({
    id: 'strict',
    ok: true,
    label: 'Fail mode',
    detail: strict ? 'fail-closed (SHOMRA_GUARD_STRICT=1)' : 'fail-open - an unreachable server lets routine calls through',
  });
  rows.push({
    id: 'subject-types',
    ok: true,
    label: 'Org subject types',
    detail: Array.isArray(subjectTypes)
      ? subjectTypes.length
        ? `${subjectTypes.length} cached (${subjectTypes.slice(0, 6).join(', ')}${subjectTypes.length > 6 ? ', …' : ''})`
        : 'cached as empty - this org has no live runtime subject rule'
      : 'unknown - every subject-bearing call is escalated until the server answers',
  });
  return rows;
}
