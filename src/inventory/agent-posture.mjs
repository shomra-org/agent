
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const HOME = os.homedir();
const PLAT = process.platform;
const MAX_SETTINGS_BYTES = 512 * 1024;

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

    const stripped = raw.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:"])\/\/.*$/gm, '$1');
    return { state: 'read', json: JSON.parse(stripped) };
  } catch (err) {
    if (err && err.code === 'ENOENT') return { state: 'absent' };

    return { state: 'unreadable', reason: err?.code === 'EACCES' ? 'permission-denied' : 'parse-failed' };
  }
}

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

const AUTO_APPROVE_KEYS = [
  { re: /^(yolo|yolomode|enableyolo)$/i, label: 'YOLO mode', severity: 'CRITICAL' },
  { re: /^(autoapprove|alwaysallow|autoallow|autoaccept|autoconfirm)$/i, label: 'auto-approve', severity: 'HIGH' },
  { re: /^(autorun|autoexecute|autoexec|runwithoutasking|executewithoutconfirmation)$/i, label: 'auto-run commands', severity: 'CRITICAL' },
  { re: /^(skippermissions|bypasspermissions|disableapproval|noconfirm)$/i, label: 'approval disabled', severity: 'CRITICAL' },
  { re: /^(autoapprovemcp|alwaysallowmcp|autotrustmcp|enableallprojectmcpservers)$/i, label: 'MCP auto-trust', severity: 'HIGH' },
  { re: /^(alwaysallowreadonly|autoapproveread)$/i, label: 'read auto-approve', severity: 'MEDIUM' },
  { re: /^(alwaysallowwrite|autoapprovewrite|autoacceptedits)$/i, label: 'write auto-approve', severity: 'HIGH' },
];

function collectSwitches(node, out, depth = 0, trail = '') {
  if (!node || typeof node !== 'object' || depth > 6 || out.length >= 40) return;
  for (const [rawKey, value] of Object.entries(node)) {

    const leaf = String(rawKey).split('.').pop() ?? rawKey;
    const normal = leaf.replace(/[_\-\s]/g, '');
    const where = trail ? `${trail}.${rawKey}` : rawKey;
    const rule = AUTO_APPROVE_KEYS.find((r) => r.re.test(normal));
    if (rule) {

      const on = value === true || value === 'true' || value === 'always' || (Array.isArray(value) && value.length > 0);
      if (on) out.push({ key: where, label: rule.label, severity: rule.severity, value: Array.isArray(value) ? `${value.length} entries` : String(value) });
    }
    if (value && typeof value === 'object') collectSwitches(value, out, depth + 1, where);
  }
}

function collectMcpServers(json) {
  const servers = json?.mcpServers ?? json?.servers ?? json?.mcp?.servers ?? null;
  if (!servers || typeof servers !== 'object' || Array.isArray(servers)) return [];
  return Object.entries(servers)
    .slice(0, 60)
    .map(([name, def]) => ({
      name,
      transport: def?.url ? 'http' : 'stdio',

      autoApprove: Array.isArray(def?.autoApprove) ? def.autoApprove.slice(0, 20) : Array.isArray(def?.alwaysAllow) ? def.alwaysAllow.slice(0, 20) : [],
      disabled: def?.disabled === true,
    }));
}

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

    autoApprovedMcp: mcpServers.filter((s) => s.autoApprove.length > 0 && !s.disabled).map((s) => s.name),

    claim: def.tier === 'declared' && read.length > 0 && holes.length === 0 ? 'complete' : 'floor',
  };
}

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

export function readPostures(vendors, cwd = process.cwd()) {
  const out = {};
  for (const v of vendors) {
    try {
      const p = readVendorPosture(v, cwd);
      if (p) out[v] = p;
    } catch {

      out[v] = { vendor: v, tier: VENDOR_POSTURE[v]?.tier ?? 'none', readable: false, sources: [], claim: 'floor', allow: [], deny: [], ask: [], switches: [], mcpServers: [], autoApprovedMcp: [], mode: null, enableAllProjectMcpServers: null, unreadableCount: 1 };
    }
  }
  return out;
}
