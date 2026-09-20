
import fs from 'node:fs';
import path from 'node:path';
import { emptyGrant, extractGrant, grantIsEmpty, parseLooseToml, parseLooseYaml, stripJsonc } from './grant-extract.mjs';
import { readMcpServers } from '../detect/signals/mcp-config.mjs';
import { CURSOR_APP_USER_KEY, INTERPRETERS, readStateKeys } from './vscode-state.mjs';
import { projectRoots } from './project-roots.mjs';
import { userDirs } from './discovery/platform.mjs';

const PLAT = process.platform;
const MAX_SETTINGS_BYTES = 512 * 1024;

export const POSTURE_TIERS = ['declared', 'flag', 'none'];

export const TIER_MEANING = {
  declared: 'The vendor documents a permission grant schema; grants are parsed and reasoned about.',
  flag: 'No grant schema. Auto-approval switches are recognised by name; a grant list cannot be enumerated.',
  none: 'No machine-readable permission surface. This agent appears in inventory only.',
};

function readJsonc(file, maxBytes = MAX_SETTINGS_BYTES) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > maxBytes) return { state: 'unreadable', reason: st.isFile() ? 'oversized' : 'not-a-file' };
    const raw = fs.readFileSync(file, 'utf8');
    if (/\.(?:toml|ya?ml)$/i.test(file)) {
      const doc = /\.toml$/i.test(file) ? parseLooseToml(raw) : parseLooseYaml(raw);
      return doc ? { state: 'read', json: doc } : { state: 'unreadable', reason: 'parse-failed' };
    }

    return { state: 'read', json: JSON.parse(stripJsonc(raw)) };
  } catch (err) {
    if (err && err.code === 'ENOENT') return { state: 'absent' };

    return { state: 'unreadable', reason: err?.code === 'EACCES' ? 'permission-denied' : 'parse-failed' };
  }
}

const COPILOT_KEYS = ['chat.', 'github.copilot'];

const EDITOR_APPS = ['Code', 'Code - Insiders', 'Cursor', 'Windsurf'];

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
      { rel: ['managed-settings.json'], base: 'claude-managed', scope: 'managed' },
      { rel: ['managed-settings.d'], base: 'claude-managed', scope: 'managed', dir: '.json' },
    ],
  },
  gemini: {
    tier: 'declared',
    label: 'Gemini CLI',
    sources: [
      { rel: ['.gemini', 'settings.json'], base: 'home', scope: 'user' },
      { rel: ['.gemini', 'settings.json'], base: 'cwd', scope: 'project' },
      { rel: ['.gemini', 'policies'], base: 'home', scope: 'user', dir: '.toml' },
      { rel: ['settings.json'], base: 'gemini-system', scope: 'managed' },
      { rel: ['system-defaults.json'], base: 'gemini-system', scope: 'managed' },
    ],
  },
  'qwen-code': {
    tier: 'declared',
    label: 'Qwen Code',
    sources: [
      { rel: ['.qwen', 'settings.json'], base: 'home', scope: 'user' },
      { rel: ['.qwen', 'settings.json'], base: 'cwd', scope: 'project' },
      { rel: ['settings.json'], base: 'qwen-system', scope: 'managed' },
    ],
  },
  codex: {
    tier: 'declared',
    label: 'OpenAI Codex CLI',
    sources: [
      { rel: ['.codex', 'config.toml'], base: 'home', scope: 'user' },
      { rel: ['.codex', 'config.toml'], base: 'cwd', scope: 'project' },
      { rel: ['.codex', 'config.json'], base: 'home', scope: 'user' },
      { rel: ['.codex', 'settings.json'], base: 'home', scope: 'user' },
    ],
  },
  cursor: {
    tier: 'declared',
    label: 'Cursor',
    sources: [
      { stateDb: 'Cursor', dbKeys: [CURSOR_APP_USER_KEY], interpret: 'cursor', scope: 'user' },
      { rel: ['.cursor', 'cli-config.json'], base: 'home', scope: 'user' },
      { rel: ['.cursor', 'permissions.json'], base: 'home', scope: 'user' },
      { rel: ['.cursor', 'sandbox.json'], base: 'home', scope: 'user' },
      { rel: ['.cursor', 'settings.json'], base: 'home', scope: 'user' },
      { rel: ['.cursor', 'mcp.json'], base: 'home', scope: 'user' },
      { rel: ['.cursor', 'cli.json'], base: 'cwd', scope: 'project' },
      { rel: ['.cursor', 'permissions.json'], base: 'cwd', scope: 'project' },
      { rel: ['.cursor', 'sandbox.json'], base: 'cwd', scope: 'project' },
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
      { rel: ['settings.json'], base: 'windsurf-user', scope: 'user', keys: ['windsurf.', 'cascade'] },
      { stateDb: 'Windsurf', dbKeys: ['windsurf%', 'codeium%'], interpret: 'windsurf', scope: 'user' },
    ],
  },
  cline: {
    tier: 'declared',
    label: 'Cline',
    sources: [
      { rel: ['settings', 'cline_mcp_settings.json'], base: 'cline-storage', scope: 'user' },
      { rel: ['.cline', 'settings.json'], base: 'home', scope: 'user' },
      { rel: ['.cline', 'data', 'globalState.json'], base: 'home', scope: 'user', interpret: 'cline', maxBytes: 8 * 1024 * 1024 },
      { rel: ['settings.json'], base: 'vscode-user', scope: 'user', keys: ['cline.'] },
      ...EDITOR_APPS.map((app) => ({ stateDb: app, dbKeys: ['saoudrizwan.claude-dev'], interpret: 'cline', scope: 'user' })),
    ],
  },
  roo: {
    tier: 'declared',
    label: 'Roo Code',
    sources: [
      { rel: ['settings', 'mcp_settings.json'], base: 'roo-storage', scope: 'user' },
      { rel: ['.roo', 'settings.json'], base: 'cwd', scope: 'project' },
      { rel: ['settings.json'], base: 'vscode-user', scope: 'user', keys: ['roo-cline.'] },
      ...EDITOR_APPS.map((app) => ({ stateDb: app, dbKeys: ['rooveterinaryinc.roo-cline'], interpret: 'roo', scope: 'user' })),
    ],
  },
  copilot: {
    tier: 'flag',
    label: 'GitHub Copilot',
    sources: [
      { rel: ['.copilot', 'config.json'], base: 'home', scope: 'user' },
      { rel: ['.copilot', 'settings.json'], base: 'home', scope: 'user' },
      { rel: ['settings.json'], base: 'vscode-user', scope: 'user', keys: COPILOT_KEYS },
      { rel: ['settings.json'], base: 'vscode-insiders-user', scope: 'user', keys: COPILOT_KEYS },
      { rel: ['.vscode', 'settings.json'], base: 'cwd', scope: 'project', keys: COPILOT_KEYS },
      { rel: ['.github', 'copilot', 'settings.json'], base: 'cwd', scope: 'project' },
      { rel: ['.github', 'copilot', 'settings.local.json'], base: 'cwd', scope: 'project' },
    ],
  },
  kiro: {
    tier: 'declared',
    label: 'Kiro',
    sources: [
      { rel: ['.kiro', 'settings', 'permissions.yaml'], base: 'home', scope: 'user' },
      { rel: ['.kiro', 'agents'], base: 'home', scope: 'user', dir: '.json' },
      { rel: ['.kiro', 'agents'], base: 'cwd', scope: 'project', dir: '.json' },
      { rel: ['.kiro', 'settings'], base: 'home', scope: 'user', dir: '.json' },
      { rel: ['.kiro', 'settings'], base: 'cwd', scope: 'project', dir: '.json' },
      { rel: ['settings.json'], base: 'vscode-user', scope: 'user', keys: ['kiroAgent.'] },
      { rel: ['.aws', 'amazonq', 'cli-agents'], base: 'home', scope: 'user', dir: '.json' },
    ],
  },
  opencode: {
    tier: 'declared',
    label: 'OpenCode',
    sources: [
      { rel: ['.config', 'opencode', 'opencode.json'], base: 'home', scope: 'user' },
      { rel: ['.config', 'opencode', 'opencode.jsonc'], base: 'home', scope: 'user' },
      { rel: ['opencode.json'], base: 'cwd', scope: 'project' },
      { rel: ['opencode.jsonc'], base: 'cwd', scope: 'project' },
    ],
  },
  zed: {
    tier: 'declared',
    label: 'Zed',
    sources: [
      { rel: ['settings.json'], base: 'zed-config', scope: 'user' },
      { rel: ['.zed', 'settings.json'], base: 'cwd', scope: 'project' },
    ],
  },
  augment: {
    tier: 'declared',
    label: 'Augment',
    sources: [
      { rel: ['.augment', 'settings.json'], base: 'home', scope: 'user' },
      { rel: ['.augment', 'settings.json'], base: 'cwd', scope: 'project' },
    ],
  },
  continue: {
    tier: 'declared',
    label: 'Continue',
    sources: [{ rel: ['.continue', 'permissions.yaml'], base: 'home', scope: 'user' }],
  },
  goose: {
    tier: 'flag',
    label: 'Goose',
    sources: [
      { rel: ['config.yaml'], base: 'goose-config', scope: 'user' },
      { rel: ['permission.yaml'], base: 'goose-config', scope: 'user' },
    ],
  },
  amp: {
    tier: 'flag',
    label: 'Amp',
    sources: [
      { rel: ['settings.json'], base: 'vscode-user', scope: 'user', keys: ['amp.'] },
      { rel: ['.config', 'amp', 'settings.json'], base: 'home', scope: 'user' },
      { rel: ['.vscode', 'settings.json'], base: 'cwd', scope: 'project', keys: ['amp.'] },
    ],
  },
  aider: {
    tier: 'flag',
    label: 'Aider',
    sources: [
      { rel: ['.aider.conf.yml'], base: 'home', scope: 'user' },
      { rel: ['.aider.conf.yml'], base: 'cwd', scope: 'project' },
    ],
  },
};

function systemDir(win, mac, linux) {
  return PLAT === 'win32' ? win : PLAT === 'darwin' ? mac : linux;
}

function resolveBase(base, cwd, home) {
  const { HOME, APPDATA, vscodeUserDir } = userDirs(home);
  switch (base) {
    case 'home': return HOME;
    case 'cwd': return cwd;
    case 'cursor-user': return path.dirname(vscodeUserDir('Cursor'));
    case 'cline-storage': return path.join(vscodeUserDir('Code'), 'globalStorage', 'saoudrizwan.claude-dev');
    case 'roo-storage': return path.join(vscodeUserDir('Code'), 'globalStorage', 'rooveterinaryinc.roo-cline');
    case 'vscode-user': return vscodeUserDir('Code');
    case 'vscode-insiders-user': return vscodeUserDir('Code - Insiders');
    case 'windsurf-user': return vscodeUserDir('Windsurf');
    case 'claude-managed': return systemDir('C:\\Program Files\\ClaudeCode', '/Library/Application Support/ClaudeCode', '/etc/claude-code');
    case 'gemini-system': return systemDir('C:\\ProgramData\\gemini-cli', '/Library/Application Support/GeminiCli', '/etc/gemini-cli');
    case 'qwen-system': return systemDir('C:\\ProgramData\\qwen-code', '/Library/Application Support/QwenCode', '/etc/qwen-code');
    case 'zed-config': return PLAT === 'win32' ? path.join(APPDATA, 'Zed') : path.join(HOME, '.config', 'zed');
    case 'goose-config': return PLAT === 'win32' ? path.join(APPDATA, 'Block', 'goose', 'config') : path.join(HOME, '.config', 'goose');
    default: return cwd;
  }
}

const MAX_DIR_FILES = 20;

function expandSource(src, cwd, home) {
  const target = path.join(resolveBase(src.base, cwd, home), ...src.rel);
  if (!src.dir) return [target];
  try {
    return fs.readdirSync(target)
      .filter((n) => n.toLowerCase().endsWith(src.dir))
      .sort()
      .slice(0, MAX_DIR_FILES)
      .map((n) => path.join(target, n));
  } catch {
    return [];
  }
}

function pickKeys(json, prefixes) {
  if (!prefixes || !json || typeof json !== 'object' || Array.isArray(json)) return json;
  return Object.fromEntries(Object.entries(json).filter(([k]) => prefixes.some((p) => k.toLowerCase().startsWith(p.toLowerCase()))));
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
  const servers = readMcpServers(json) ?? [];
  return servers.slice(0, 60).map((s) => ({
    name: s.name,
    transport: s.url ? 'http' : 'stdio',
    autoApprove: (s.trusted ? ['*', ...(s.autoApprove ?? [])] : s.autoApprove ?? []).slice(0, 20),
    disabled: s.disabled === true,
  }));
}

function readSource(src, cwd, home) {
  if (src.stateDb) {
    const file = path.join(userDirs(home).vscodeUserDir(src.stateDb), 'globalStorage', 'state.vscdb');
    const res = readStateKeys(file, src.dbKeys);
    const docs = res.state === 'read' ? res.values.map((v) => INTERPRETERS[src.interpret](v.json)) : [];
    return [{ path: `${file}#${src.dbKeys.join('|')}`, res, docs }];
  }
  return expandSource(src, cwd, home).map((file) => {
    const res = readJsonc(file, src.maxBytes);
    const raw = res.state === 'read' ? pickKeys(res.json ?? {}, src.keys) : null;
    const doc = raw && src.interpret ? INTERPRETERS[src.interpret](raw) : raw;
    return { path: file, res, docs: doc ? [doc] : [] };
  });
}

export function readVendorPosture(vendor, cwd = process.cwd(), roots = null, opts = {}) {
  const def = VENDOR_POSTURE[vendor];
  if (!def) return null;

  const sources = [];
  const switches = [];
  const mcpServers = [];
  const grant = emptyGrant();
  const extraRoots = (roots ?? []).filter((r) => r && path.resolve(r) !== path.resolve(cwd));
  const projectsRead = new Set();

  for (const src of def.sources) {
    const bases = src.base === 'cwd' ? [cwd, ...extraRoots] : [cwd];
    for (const base of bases) {
      for (const { path: file, res, docs } of readSource(src, base, opts.home)) {
        const primary = base === cwd;
        if (primary || res.state !== 'absent') sources.push({ path: file, scope: src.scope, state: res.state, reason: res.reason ?? null });
        if (res.state !== 'read') continue;
        if (src.base === 'cwd') projectsRead.add(base);
        for (const json of docs) {
          if ((src.keys || src.interpret) && !Object.keys(json).length) continue;
          extractGrant(json, grant);
          if (def.tier === 'flag') collectSwitches(json, switches);
          for (const s of collectMcpServers(json)) if (!mcpServers.some((x) => x.name === s.name)) mcpServers.push(s);
        }
      }
    }
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
    mode: grant.mode,
    allow: grant.allow.slice(0, 60),
    deny: grant.deny.slice(0, 60),
    ask: grant.ask.slice(0, 60),
    enableAllProjectMcpServers: grant.enableAllProjectMcpServers,
    grant,
    switches: switches.slice(0, 20),
    mcpServers,

    autoApprovedMcp: mcpServers.filter((s) => s.autoApprove.length > 0 && !s.disabled).map((s) => s.name),

    truncated: grant.truncated === true,
    projectsScanned: 1 + extraRoots.length,
    projectsWithSettings: projectsRead.size,
    claim: def.tier === 'declared' && read.length > 0 && holes.length === 0 && !grant.truncated ? 'complete' : 'floor',
  };
}

export function canonicalGrant(posture) {
  if (!posture) return null;
  const g = posture.grant && !grantIsEmpty(posture.grant) ? posture.grant : null;
  const doc = {};
  const perms = {};
  if (posture.mode) perms.defaultMode = posture.mode;
  if (posture.allow?.length) perms.allow = posture.allow;
  if (posture.deny?.length) perms.deny = posture.deny;
  if (posture.ask?.length) perms.ask = posture.ask;
  if (g) {
    if (g.directories.length) perms.additionalDirectories = g.directories;
    if (g.trustedFolders.length) perms.trustedFolders = g.trustedFolders;
    const fsGrant = Object.fromEntries(Object.entries(g.fileSystem).filter(([, v]) => v.length));
    if (Object.keys(fsGrant).length) perms.fileSystem = fsGrant;
    const net = Object.fromEntries(Object.entries(g.network).filter(([, v]) => v.length));
    if (Object.keys(net).length) perms.network = net;
    if (g.envNames.length) perms.environmentVariables = { allowList: g.envNames };
    if (g.commands.length) perms.tools = { allowExecution: g.commands };
    if (g.rules.length) perms.rules = g.rules;
    if (g.permission) perms.permission = g.permission;
    if (g.toolPermissions && Object.keys(g.toolPermissions).length) perms.tool_permissions = g.toolPermissions;
    if (g.unixSockets.length) perms.sandbox = { network: { allowUnixSockets: g.unixSockets } };
    if (g.mcpAllowlist.length) perms.mcpAllowlist = g.mcpAllowlist;
    if (g.folderTrustDisabled) perms.folderTrust = { enabled: false };
    for (const [k, v] of Object.entries(g.flags)) if (!(k in perms)) perms[k] = v;
  }
  if (Object.keys(perms).length) doc.permissions = perms;
  if (posture.enableAllProjectMcpServers === true) doc.enableAllProjectMcpServers = true;
  return Object.keys(doc).length ? JSON.stringify(doc, null, 2) : null;
}

export function readPostures(vendors, cwd = process.cwd(), roots = projectRoots(cwd)) {
  const out = {};
  for (const v of vendors) {
    try {
      const p = readVendorPosture(v, cwd, roots);
      if (p) out[v] = p;
    } catch {

      out[v] = { vendor: v, tier: VENDOR_POSTURE[v]?.tier ?? 'none', readable: false, sources: [], claim: 'floor', allow: [], deny: [], ask: [], switches: [], mcpServers: [], autoApprovedMcp: [], mode: null, enableAllProjectMcpServers: null, unreadableCount: 1 };
    }
  }
  return out;
}
