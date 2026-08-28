/**
 * CODING-AGENT PERMISSION POSTURE — what an installed agent is allowed to do on
 * this machine, without asking anyone.
 *
 * `discovery.mjs` already answers "which coding agents are on this laptop". That
 * is the question every endpoint tool answers, and it is the less useful half:
 * knowing Cursor is installed on 200 machines tells a security team nothing they
 * can act on. The actionable fact is the GRANT — that on 41 of those machines it
 * auto-approves an MCP server with network egress, and on 6 the agent runs with
 * the approval prompt disabled entirely.
 *
 * That fact is sitting in a JSON file next to the one we already open.
 *
 * ── What leaves the machine ──────────────────────────────────────────────────
 *
 * The GRANT SHAPE, never the file. This module extracts only the permission keys
 * into a canonical document and ships that; the rest of a developer's settings —
 * their theme, their API keys, their local paths, their prompts — is read and
 * discarded here and never enters the report. A posture tool that uploads
 * `~/.claude.json` wholesale to make its detection easier has quietly become the
 * exfiltration path it sells against, and no amount of server-side scrubbing
 * makes that the right default.
 *
 * ── The tier, and why it is declared per vendor ──────────────────────────────
 *
 * These agents do not have one permission model, and pretending otherwise is the
 * failure this module is built to avoid. Claude Code documents a permission
 * schema that can be parsed structurally and reasoned about. Cursor does not: it
 * has settings that gate auto-running, spelled in product-specific keys with no
 * published contract. Aider is configured in YAML with flags, not grants.
 *
 * So each vendor declares what is actually knowable about it:
 *
 *   DECLARED  the vendor documents a permission grant schema. We parse it and
 *             reason about what it PERMITS. Real, structural coverage.
 *   FLAG      no grant schema. We recognise auto-approval switches by name and
 *             report those. Finds the switch that is on; cannot enumerate a
 *             grant, because there is nothing to enumerate.
 *   NONE      no machine-readable permission surface. Inventory only.
 *
 * ⚠ THE CARDINAL RULE, same as hosted-platforms.ts: a vendor's posture is
 * reported at its TRUE tier and never rounded up. A FLAG-tier agent with no
 * switches found is NOT "least privilege" — it is "we looked at the two things
 * we can see". Rendering that as a clean posture is the single most damaging lie
 * this module could tell, because it is discovered during the incident it was
 * supposed to prevent.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const HOME = os.homedir();
const PLAT = process.platform;
const MAX_SETTINGS_BYTES = 512 * 1024;

/** How much can actually be known about this vendor's permissions. */
export const POSTURE_TIERS = ['declared', 'flag', 'none'];

export const TIER_MEANING = {
  declared: 'The vendor documents a permission grant schema; grants are parsed and reasoned about.',
  flag: 'No grant schema. Auto-approval switches are recognised by name; a grant list cannot be enumerated.',
  none: 'No machine-readable permission surface. This agent appears in inventory only.',
};

function readJsonc(file) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > MAX_SETTINGS_BYTES) return { state: 'unreadable', reason: st.isFile() ? 'oversized' : 'not-a-file' };
    const raw = fs.readFileSync(file, 'utf8');
    // VS Code-family settings are JSONC. Tolerating comments here is not
    // cosmetic: a strict parse fails on a perfectly ordinary Cursor config, and
    // a parse failure reads downstream as "nothing configured".
    const stripped = raw.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:"])\/\/.*$/gm, '$1');
    return { state: 'read', json: JSON.parse(stripped) };
  } catch (err) {
    if (err && err.code === 'ENOENT') return { state: 'absent' };
    // A file that exists and will not parse is a HOLE, distinct from one that is
    // not there. Collapsing the two would let a corrupt settings file read as an
    // unconfigured agent.
    return { state: 'unreadable', reason: err?.code === 'EACCES' ? 'permission-denied' : 'parse-failed' };
  }
}

/**
 * Where each vendor keeps its permission surface, and what can be read there.
 *
 * `scope: 'user'` files govern EVERY project on the machine, which is what makes
 * them worth the endpoint agent's existence — a repo scan structurally cannot
 * see them, because they are not in any repo.
 */
export const VENDOR_POSTURE = {
  'claude-code': {
    tier: 'declared',
    label: 'Claude Code',
    sources: [
      { rel: ['.claude', 'settings.json'], base: 'home', scope: 'user' },
      { rel: ['.claude.json'], base: 'home', scope: 'user' },
      { rel: ['.claude', 'settings.local.json'], base: 'home', scope: 'user' },
      { rel: ['.claude', 'settings.json'], base: 'cwd', scope: 'project' },
      { rel: ['.claude', 'settings.local.json'], base: 'cwd', scope: 'project' },
    ],
  },
  gemini: {
    tier: 'declared',
    label: 'Gemini CLI',
    sources: [
      { rel: ['.gemini', 'settings.json'], base: 'home', scope: 'user' },
      { rel: ['.gemini', 'settings.json'], base: 'cwd', scope: 'project' },
    ],
  },
  codex: {
    tier: 'declared',
    label: 'OpenAI Codex CLI',
    sources: [
      { rel: ['.codex', 'config.json'], base: 'home', scope: 'user' },
      { rel: ['.codex', 'settings.json'], base: 'home', scope: 'user' },
    ],
  },
  cursor: {
    tier: 'flag',
    label: 'Cursor',
    sources: [
      { rel: ['.cursor', 'settings.json'], base: 'home', scope: 'user' },
      { rel: ['.cursor', 'mcp.json'], base: 'home', scope: 'user' },
      { rel: ['.cursor', 'mcp.json'], base: 'cwd', scope: 'project' },
      { rel: ['.cursor', 'settings.json'], base: 'cwd', scope: 'project' },
      { rel: ['User', 'settings.json'], base: 'cursor-user', scope: 'user' },
    ],
  },
  windsurf: {
    tier: 'flag',
    label: 'Windsurf',
    sources: [
      { rel: ['.codeium', 'windsurf', 'settings.json'], base: 'home', scope: 'user' },
      { rel: ['.codeium', 'windsurf', 'mcp_config.json'], base: 'home', scope: 'user' },
      { rel: ['.windsurf', 'mcp.json'], base: 'cwd', scope: 'project' },
    ],
  },
  cline: {
    tier: 'flag',
    label: 'Cline',
    sources: [
      { rel: ['settings', 'cline_mcp_settings.json'], base: 'cline-storage', scope: 'user' },
      { rel: ['.cline', 'settings.json'], base: 'home', scope: 'user' },
    ],
  },
  roo: {
    tier: 'flag',
    label: 'Roo Code',
    sources: [
      { rel: ['settings', 'mcp_settings.json'], base: 'roo-storage', scope: 'user' },
      { rel: ['.roo', 'settings.json'], base: 'cwd', scope: 'project' },
    ],
  },
  copilot: {
    tier: 'flag',
    label: 'GitHub Copilot CLI',
    sources: [{ rel: ['.copilot', 'config.json'], base: 'home', scope: 'user' }],
  },
  // Aider is configured through a YAML file and command-line flags. There is no
  // JSON grant surface to parse, and half-parsing YAML to guess at flags would
  // produce a posture nobody should trust. Declared `none` instead.
  aider: { tier: 'none', label: 'Aider', sources: [] },
};

function vscodeUserDir(variant) {
  if (PLAT === 'win32') return path.join(process.env.APPDATA || path.join(HOME, 'AppData', 'Roaming'), variant, 'User');
  if (PLAT === 'darwin') return path.join(HOME, 'Library', 'Application Support', variant, 'User');
  return path.join(HOME, '.config', variant, 'User');
}

function resolveBase(base, cwd) {
  switch (base) {
    case 'home': return HOME;
    case 'cwd': return cwd;
    case 'cursor-user': return path.dirname(vscodeUserDir('Cursor'));
    case 'cline-storage': return path.join(vscodeUserDir('Code'), 'globalStorage', 'saoudrizwan.claude-dev');
    case 'roo-storage': return path.join(vscodeUserDir('Code'), 'globalStorage', 'rooveterinaryinc.roo-cline');
    default: return cwd;
  }
}

/**
 * Auto-approval switches, by NAME, for the vendors that publish no grant schema.
 *
 * Deliberately a name list rather than a shape parse: without a documented
 * schema there is no shape to parse, and inventing one would mean asserting a
 * contract the vendor never made. What CAN be said honestly is "a setting called
 * this is set to true", which is exactly what this reports.
 *
 * Matching is on the LEAF key, case-insensitively, anywhere in the settings
 * object — these products nest their settings under product-prefixed namespaces
 * that change between releases, and pinning the full path is how a check goes
 * silently blind on an update.
 */
const AUTO_APPROVE_KEYS = [
  { re: /^(yolo|yolomode|enableyolo)$/i, label: 'YOLO mode', severity: 'CRITICAL' },
  { re: /^(autoapprove|alwaysallow|autoallow|autoaccept|autoconfirm)$/i, label: 'auto-approve', severity: 'HIGH' },
  { re: /^(autorun|autoexecute|autoexec|runwithoutasking|executewithoutconfirmation)$/i, label: 'auto-run commands', severity: 'CRITICAL' },
  { re: /^(skippermissions|bypasspermissions|disableapproval|noconfirm)$/i, label: 'approval disabled', severity: 'CRITICAL' },
  { re: /^(autoapprovemcp|alwaysallowmcp|autotrustmcp|enableallprojectmcpservers)$/i, label: 'MCP auto-trust', severity: 'HIGH' },
  { re: /^(alwaysallowreadonly|autoapproveread)$/i, label: 'read auto-approve', severity: 'MEDIUM' },
  { re: /^(alwaysallowwrite|autoapprovewrite|autoacceptedits)$/i, label: 'write auto-approve', severity: 'HIGH' },
];

/** Walk an arbitrary settings object collecting auto-approval switches that are ON. */
function collectSwitches(node, out, depth = 0, trail = '') {
  if (!node || typeof node !== 'object' || depth > 6 || out.length >= 40) return;
  for (const [rawKey, value] of Object.entries(node)) {
    // Product namespaces (`cursor.composer.autoRun`) arrive as one dotted key.
    const leaf = String(rawKey).split('.').pop() ?? rawKey;
    const normal = leaf.replace(/[_\-\s]/g, '');
    const where = trail ? `${trail}.${rawKey}` : rawKey;
    const rule = AUTO_APPROVE_KEYS.find((r) => r.re.test(normal));
    if (rule) {
      // Only an ENABLED switch is reported. A settings file that explicitly turns
      // auto-approve OFF is the good case, and reporting it would train people to
      // ignore the whole row.
      const on = value === true || value === 'true' || value === 'always' || (Array.isArray(value) && value.length > 0);
      if (on) out.push({ key: where, label: rule.label, severity: rule.severity, value: Array.isArray(value) ? `${value.length} entries` : String(value) });
    }
    if (value && typeof value === 'object') collectSwitches(value, out, depth + 1, where);
  }
}

/** MCP servers declared in a settings document, with their auto-approve lists. */
function collectMcpServers(json) {
  const servers = json?.mcpServers ?? json?.servers ?? json?.mcp?.servers ?? null;
  if (!servers || typeof servers !== 'object' || Array.isArray(servers)) return [];
  return Object.entries(servers)
    .slice(0, 60)
    .map(([name, def]) => ({
      name,
      transport: def?.url ? 'http' : 'stdio',
      // The autoApprove list is the per-server version of the global switch: it
      // names exactly which tools run with no prompt.
      autoApprove: Array.isArray(def?.autoApprove) ? def.autoApprove.slice(0, 20) : Array.isArray(def?.alwaysAllow) ? def.alwaysAllow.slice(0, 20) : [],
      disabled: def?.disabled === true,
    }));
}

/**
 * Read one vendor's permission posture off this machine.
 *
 * Never throws: an unreadable source is recorded as a hole and the read
 * continues. A posture collector that dies on one malformed file reports nothing
 * about the other eight agents on the machine.
 */
export function readVendorPosture(vendor, cwd = process.cwd()) {
  const def = VENDOR_POSTURE[vendor];
  if (!def) return null;

  const sources = [];
  const switches = [];
  const mcpServers = [];
  let mode = null;
  const allow = [];
  const deny = [];
  const ask = [];
  let enableAllProjectMcpServers = null;

  for (const src of def.sources) {
    const file = path.join(resolveBase(src.base, cwd), ...src.rel);
    const res = readJsonc(file);
    sources.push({ path: file, scope: src.scope, state: res.state, reason: res.reason ?? null });
    if (res.state !== 'read') continue;

    const json = res.json ?? {};
    const perms = json.permissions ?? {};
    // Worst-wins across sources: a project file that relaxes the mode is the
    // effective posture for that project, and reporting only the user-level
    // default would describe a machine nobody is actually running.
    const m = perms.defaultMode ?? json.defaultMode ?? null;
    if (m && (!mode || String(m).toLowerCase() === 'bypasspermissions')) mode = String(m);
    for (const [key, sink] of [['allow', allow], ['deny', deny], ['ask', ask]]) {
      const list = Array.isArray(perms[key]) ? perms[key] : key === 'allow' && Array.isArray(json.allowedTools) ? json.allowedTools : [];
      for (const g of list) if (typeof g === 'string' && !sink.includes(g)) sink.push(g);
    }
    if (json.enableAllProjectMcpServers === true) enableAllProjectMcpServers = true;
    else if (enableAllProjectMcpServers === null && json.enableAllProjectMcpServers === false) enableAllProjectMcpServers = false;

    if (def.tier === 'flag') collectSwitches(json, switches);
    for (const s of collectMcpServers(json)) if (!mcpServers.some((x) => x.name === s.name)) mcpServers.push(s);
  }

  const read = sources.filter((s) => s.state === 'read');
  const holes = sources.filter((s) => s.state === 'unreadable');

  return {
    vendor,
    tier: def.tier,
    label: def.label,
    /** True only when at least one permission source actually parsed. */
    readable: read.length > 0,
    sources,
    unreadableCount: holes.length,
    mode,
    allow: allow.slice(0, 60),
    deny: deny.slice(0, 60),
    ask: ask.slice(0, 60),
    enableAllProjectMcpServers,
    switches: switches.slice(0, 20),
    mcpServers,
    /** MCP servers with a non-empty per-server auto-approve list. */
    autoApprovedMcp: mcpServers.filter((s) => s.autoApprove.length > 0 && !s.disabled).map((s) => s.name),
    /**
     * ⚠ The honesty field. `complete` means a DECLARED-tier vendor whose sources
     * all parsed. Everything else is a lower bound: a FLAG-tier vendor can only
     * report the switches it knows the names of, and a `none`-tier vendor cannot
     * report a posture at all. Consumers must not render `floor` as a clean
     * result — see the module header.
     */
    claim: def.tier === 'declared' && read.length > 0 && holes.length === 0 ? 'complete' : 'floor',
  };
}

/**
 * The canonical grant document shipped to the backend.
 *
 * ONLY permission keys. This is the boundary the module header promises: the
 * settings files are read on the machine and this is the whole of what leaves
 * it. It is deliberately shaped to match what `checks/agent-permissions.ts`
 * already parses, so the endpoint plane and the repo scan grade an identical
 * grant identically instead of growing two opinions about `Bash(*)`.
 */
export function canonicalGrant(posture) {
  if (!posture) return null;
  const doc = {};
  const perms = {};
  if (posture.mode) perms.defaultMode = posture.mode;
  if (posture.allow.length) perms.allow = posture.allow;
  if (posture.deny.length) perms.deny = posture.deny;
  if (posture.ask.length) perms.ask = posture.ask;
  if (Object.keys(perms).length) doc.permissions = perms;
  if (posture.enableAllProjectMcpServers === true) doc.enableAllProjectMcpServers = true;
  return Object.keys(doc).length ? JSON.stringify(doc, null, 2) : null;
}

/**
 * Posture for every vendor the caller found installed.
 *
 * @param vendors installed vendor ids, from discoverCodingAgents
 */
export function readPostures(vendors, cwd = process.cwd()) {
  const out = {};
  for (const v of vendors) {
    try {
      const p = readVendorPosture(v, cwd);
      if (p) out[v] = p;
    } catch {
      // Best-effort per vendor, like every other discoverer in this package.
      out[v] = { vendor: v, tier: VENDOR_POSTURE[v]?.tier ?? 'none', readable: false, sources: [], claim: 'floor', allow: [], deny: [], ask: [], switches: [], mcpServers: [], autoApprovedMcp: [], mode: null, enableAllProjectMcpServers: null, unreadableCount: 1 };
    }
  }
  return out;
}
