
const MAX_DEPTH = 12;
const MAX_NODES = 5000;
const MAX_ARRAY_OBJECTS = 200;
const LIST_CAP = 30;
const STR_CAP = 200;

export const norm = (k) => String(k).normalize('NFKC').toLowerCase().replace(/[^a-z0-9]/g, '');

export const MODE_KEYS = new Set([
  'defaultmode', 'mode', 'permissionmode', 'approvalmode', 'defaultapprovalmode', 'agentmode',
  'executionmode', 'runmode', 'autonomy', 'autonomylevel', 'approvalpolicy', 'askforapproval',
  'agentautonomy', 'autoexecutionlevel', 'autoexecutionpolicy',
]);

const FULL_MODE_KEYS = new Set(['chatpermissionsdefault']);

const GENERIC_MODE_VALUES = new Set(['bypasspermissions', 'yolo', 'acceptedits', 'autoedit', 'autonomous', 'fullauto']);

export const MODE_RANK = {
  bypasspermissions: 5, yolo: 5, never: 5,
  autonomous: 4, fullauto: 4, unattended: 4, unrestricted: 4, autopilot: 4, allowall: 4, noapproval: 4, autoapprove: 4, turbo: 4, runeverything: 4,
  acceptedits: 2, autoedit: 2,
};

const FLAG_KEY = new RegExp(
  '^(?:' + [
    'yolo', 'yolomode', 'enableyolo', 'dangerouslyskippermissions', 'skippermissions', 'bypasspermissions', 'disableapprovals?', 'noconfirm',
    'autorun', 'autoexecute', 'runwithoutasking', 'executewithoutconfirmation', 'allowalltools', 'enablealltools', 'autoapprovealltools',
    'executeallcommands', 'chattoolsautoapprove', 'chattoolsglobalautoapprove', 'chattoolsurlsautoapprove',
    'alwaysallowtoolactions', 'yolomodetoggled', 'alwaysallowexecute', 'trustalltools', 'skippermissionrequests', 'dangerouslyallowall', 'yoloenableruneverything', 'useyolomode', 'editfilesexternally',
    'alwaysallowwriteoutsideworkspace', 'alwaysallowwriteprotected', 'alwaysallowreadonlyoutsideworkspace', 'autoapprovalenabled',
    'alwaysallowbrowser', 'alwaysallowsubtasks', 'allowbypass', 'goosemode', 'defaultpermissions',
    '(?:bypass|skip|disable|suppress|ignore|no|without|turnoff)(?:all)?(?:user)?(?:consent|approvals?|confirmations?|confirm|prompts?|permissions?|permissionchecks?|humanreview|hitl|safetychecks?|guardrails?)(?:prompts?|checks?|dialogs?|requests?)?',
    '(?:disable|no|bypass|skip|without|turnoff)sandbox(?:ing)?', 'dangerouslydisablesandbox', 'unsandboxed', 'allowunsandboxed',
    'sandbox', 'sandboxed', 'sandboxenabled', 'enablesandbox', 'usesandbox', 'sandboxing', 'sandboxmode',
    'autoapprove', 'alwaysallow', 'autoallow', 'autoaccept', 'autoconfirm', 'fullauto', 'yesalways', 'trustall', 'autoapprovetools',
    'autoacceptedits', 'alwaysallowwrite', 'autoapprovewrite',
    'requireapproval', 'requireconfirmation', 'requirehumanapproval', 'humanintheloop', 'hitl', 'confirmbeforeexecute', 'confirmbeforerun',
    'confirmcommands', 'askbeforerunning', 'promptbeforeexecute', 'approvalrequired', 'confirmationrequired', 'confirmactions',
    'autoapprovemcp', 'alwaysallowmcp', 'autotrustmcp', 'trustallmcpservers', 'enableallmcpservers',
    'exposeall', 'exposeallenv', 'inheritall', 'passall', 'passthroughall', 'shareallenv', 'exposeenvironment', 'inheritenvironment', 'ignoredefaultexcludes',
    'allowbackgroundexecution', 'backgroundexecution', 'allowbackgroundprocesses', 'allowbackgroundtasks', 'allowdetachedprocesses', 'persistentprocesses', 'allowdaemons',
    'disableallhooks', 'skipdangerousmodepermissionprompt', 'networkaccess', 'allownetwork', 'networkenabled',
  ].join('|') + ')$',
);

const SKIP_SUBTREES = new Set([
  'mcpservers', 'servers', 'contextservers', 'hooks', 'env', 'environment', 'history', 'projects', 'oauthaccount',
  'deny', 'disallowedtools', 'ask', 'excludetools', 'blocklist', 'denylist',
]);

const FS_PARENT = /^(?:filesystem|fs|files|fileaccess|filesystemaccess|paths|disk|storage)$/;
const NET_PARENT = /^(?:network|net|networking|networkaccess|sandboxnetwork|networkpolicy|networkproxy)$/;
const ANYWHERE_FS_KEYS = { writableroots: 'write', additionalreadwritepaths: 'write', additionalwritablepaths: 'write', additionalreadonlypaths: 'read' };
const PATH_LIST_PARENTS = { write: 'write', fswrite: 'write', edit: 'write', read: 'read', fsread: 'read' };
const ALLOW_DECISION = new Set(['allow', 'alwaysallow', 'autoapprove', 'approve', 'auto']);
const ENV_PARENT = /^(?:environmentvariables|envvars|envvariables|environmentvars|envaccess|environmentaccess|envpolicy|environmentpolicy|shellenvironmentpolicy|secrets)$/;
const TOOLS_PARENT = /^(?:tools|shell|terminal|commands|exec|execution|process|processes)$/;

const FS_KEYS = {
  read: 'read', readpaths: 'read', allowread: 'read', readable: 'read', readonly: 'read',
  write: 'write', writepaths: 'write', allowwrite: 'write', writable: 'write', readwrite: 'write', modify: 'write',
  execute: 'execute', exec: 'execute', executepaths: 'execute', allowexecute: 'execute', executable: 'execute', run: 'execute',
};
const OUTBOUND_KEYS = /^(?:outbound|egress|alloweddomains|allowedhosts|allowlist|allow|domains|hosts|destinations|allowedurls|allowedorigins|networkallowlist)$/;
const INBOUND_KEYS = /^(?:inbound|ingress|listen|allowinbound|incoming)$/;
const ENV_LIST_KEYS = /^(?:read|allow|allowlist|allowed|expose|exposed|include|includeonly|passthrough|share|whitelist|keys|names)$/;
const TOOLS_EXEC_KEYS = /^(?:allowexecution|allowexec|allowedexecution|execute|exec|commands|allowedcommands|executables|binaries|programs)$/;
const EXEC_LIST_KEYS = /^(?:allow|allowed|allowlist|allowexecution|allowexec|execute|exec|run|commands|allowedcommands|executables|binaries|programs)$/;
const COMMAND_LIST_KEYS = /^(?:allowedcommands|allowcommands|commandallowlist|shellcommands|allowedexecutables|allowedbinaries|terminalallowlist|cascadecommandsallowlist|trustedcommands|ampcommandsallowlist|yolocommandallowlist)$/;
const DIRECTORY_KEYS = /^(?:additionaldirectories|alloweddirectories|workspaces|workingdirectories)$/;
const TRUST_KEYS = /^(?:trustedfolders|trustedprojects)$/;

const SETTINGS_MARKER = /^(?:permissions|permission|defaultmode|allowedtools|disallowedtools|enableallprojectmcpservers|approvalpolicy|approvalmode|defaultapprovalmode|sandboxmode|defaultpermissions|autoapprovalsettings|dangerouslyskippermissions|skipdangerousmodepermissionprompt|filesystem|network|networkpolicy|allowbackgroundexecution|environmentvariables|chattoolsautoapprove|chattoolsglobalautoapprove|chattoolsterminalautoapprove|chatpermissionsdefault|yolo|yolomodetoggled|autoapprove|alwaysallow|alwaysallowexecute|alwaysallowtoolactions|autoapprovalenabled|additionaldirectories|additionalreadwritepaths|writableroots|trustedfolders|shellenvironmentpolicy|toolpermissions|goosemode|yesalways|rule|terminalallowlist|mcpallowlist|allowedcommands|cascadecommandsallowlist|agentautonomy|skippermissionrequests|foldertrust|type|dangerouslyallowall|ampcommandsallowlist)$/;

const SECRETISH = /(?:sk-[A-Za-z0-9_-]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[abpr]-|eyJ[A-Za-z0-9_-]{10,}\.|-----BEGIN)/;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

const asList = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string') : typeof v === 'string' ? [v] : []);

function clean(s) {
  const t = String(s).slice(0, STR_CAP).replace(/^([a-z]+:\/\/)[^/@\s]*@/i, '$1');
  return SECRETISH.test(t) ? null : t;
}

function addAll(sink, values) {
  for (const v of values) {
    const c = clean(v);
    if (c !== null && !sink.includes(c) && sink.length < LIST_CAP) sink.push(c);
  }
}

function flagValue(v) {
  if (typeof v === 'boolean' || (typeof v === 'number' && Number.isFinite(v))) return v;
  if (typeof v === 'string' && v.length <= 40 && /^[\w .:/*@-]*$/.test(v) && !SECRETISH.test(v)) return v;
  if (Array.isArray(v) && v.some((x) => typeof x === 'string' && /^\s*(?:\*+|all|\.\*|any)\s*$/i.test(x))) return ['*'];
  return undefined;
}

function isSettingsNode(node) {
  if (!isObj(node)) return false;
  if (Array.isArray(node.allow) && ['ask', 'exclude', 'deny'].some((k) => Array.isArray(node[k]))) return true;
  if ((node.decision ?? node.effect) !== undefined && (node.toolName ?? node.capability ?? node.tool ?? node.mcpName) !== undefined) return true;
  return Object.entries(node).some(([k, v]) => (norm(k) === 'permissions' ? isObj(v) : SETTINGS_MARKER.test(norm(k)) || SETTINGS_MARKER.test(leafNorm(k))));
}

export function findSettingsNode(doc) {
  const queue = [{ node: doc, depth: 0 }];
  let seen = 0;
  while (queue.length && seen++ < MAX_NODES) {
    const { node, depth } = queue.shift();
    if (isSettingsNode(node)) return node;
    if (depth >= 5 || !node || typeof node !== 'object') continue;
    if (Array.isArray(node)) {
      for (const el of node.slice(0, MAX_ARRAY_OBJECTS)) if (isObj(el)) queue.push({ node: el, depth: depth + 1 });
      continue;
    }
    for (const [k, v] of Object.entries(node)) if (v && typeof v === 'object' && !SKIP_SUBTREES.has(leafNorm(k))) queue.push({ node: v, depth: depth + 1 });
  }
  return null;
}

export function emptyGrant() {
  return {
    mode: null,
    allow: [], deny: [], ask: [],
    flags: {},
    fileSystem: { read: [], write: [], execute: [] },
    network: { outbound: [], inbound: [] },
    envNames: [],
    commands: [],
    directories: [],
    trustedFolders: [],
    rules: [],
    permission: null,
    toolPermissions: null,
    unixSockets: [],
    mcpAllowlist: [],
    folderTrustDisabled: false,
    enableAllProjectMcpServers: null,
  };
}

const DECISIONS = new Set(['allow', 'ask', 'deny']);

function collectRule(g, node) {
  const perm = node.permission;
  const decision = node.decision ?? node.effect ?? node.action ?? (typeof perm === 'string' ? perm : isObj(perm) ? perm.type : undefined);
  if (typeof decision !== 'string' || !ALLOW_DECISION.has(norm(decision)) || g.rules.length >= LIST_CAP) return;
  const tools = asList(node.toolName ?? node.tool_name ?? node.tool ?? node.capability).map(clean).filter(Boolean).slice(0, 10);
  const mcpName = typeof node.mcpName === 'string' ? clean(node.mcpName) : null;
  if (!tools.length && !mcpName) return;
  const rawPattern = asList(node.commandPrefix ?? node.commandRegex ?? node.match ?? node.shellInputRegex ?? node.pattern ?? node.argsPattern)[0];
  const pattern = rawPattern !== undefined ? clean(rawPattern) : null;
  g.rules.push({ ...(tools.length ? { toolName: tools } : {}), ...(mcpName ? { mcpName } : {}), ...(pattern ? { pattern } : {}), decision: 'allow' });
}

function collectPermissionMap(g, value) {
  if (typeof value === 'string') {
    if (norm(value) === 'allow') g.permission = 'allow';
    return;
  }
  if (!isObj(value)) return;
  const out = isObj(g.permission) ? g.permission : {};
  for (const [tool, decision] of Object.entries(value).slice(0, 40)) {
    const t = clean(tool);
    if (!t) continue;
    if (typeof decision === 'string' && DECISIONS.has(norm(decision))) out[t] = norm(decision);
    else if (isObj(decision)) {
      const map = {};
      for (const [pat, d] of Object.entries(decision).slice(0, LIST_CAP)) {
        const cp = clean(pat);
        if (cp !== null && typeof d === 'string' && DECISIONS.has(norm(d))) map[cp] = norm(d);
      }
      if (Object.keys(map).length) out[t] = map;
    }
  }
  if (Object.keys(out).length && g.permission !== 'allow') g.permission = out;
}

function collectToolPermissions(g, k, value) {
  const tp = g.toolPermissions ?? (g.toolPermissions = {});
  if (k === 'default' && typeof value === 'string') tp.default = norm(value).slice(0, 20);
  if (k !== 'tools' || !isObj(value)) return;
  tp.tools = tp.tools ?? {};
  for (const [tool, cfg] of Object.entries(value).slice(0, 40)) {
    if (!isObj(cfg)) continue;
    const entry = {};
    if (typeof cfg.default === 'string') entry.default = norm(cfg.default);
    const patterns = (Array.isArray(cfg.always_allow) ? cfg.always_allow : [])
      .map((e) => (typeof e === 'string' ? e : typeof e?.pattern === 'string' ? e.pattern : null))
      .filter((x) => x !== null).map(clean).filter((x) => x !== null).slice(0, LIST_CAP);
    if (patterns.length) entry.always_allow = patterns.map((pattern) => ({ pattern }));
    if (Object.keys(entry).length) tp.tools[clean(tool) ?? 'tool'] = entry;
  }
}

function takeMode(g, value) {
  const v = String(value);
  const rank = MODE_RANK[norm(v)] ?? 1;
  const cur = g.mode ? MODE_RANK[norm(g.mode)] ?? 1 : 0;
  if (!g.mode || rank > cur) g.mode = v.slice(0, 40);
}

const TOGGLE_CONTAINER = /^(?:autoapprovalsettings|autoapprove|autorun|autoexecute|yolo|yolomode|fullauto|autoaccept)$/;
const PRIORITY_CHILD = /^(?:permissions?|agentsettings|settings|agent|agents|sandbox|sandboxworkspacewrite|tools|toolssettings|toolpermissions|filesystem|network|environmentvariables|shellenvironmentpolicy|autoapprovalsettings|security|general|profiles|chat)$/;

export const leafNorm = (rawKey) => {
  const s = String(rawKey);
  return s.includes('.') ? norm(s.slice(s.lastIndexOf('.') + 1)) : norm(s);
};

function ordered(node) {
  const rank = ([k, v]) => (!v || typeof v !== 'object' ? 0 : PRIORITY_CHILD.test(leafNorm(k)) ? 1 : 2);
  return Object.entries(node).sort((a, b) => rank(a) - rank(b));
}

function walk(g, node, depth, parent, budget) {
  if (!node || typeof node !== 'object') return;
  if (depth > MAX_DEPTH || budget.n >= MAX_NODES) {
    g.truncated = true;
    return;
  }
  budget.n++;
  if (Array.isArray(node)) {
    if (node.length > MAX_ARRAY_OBJECTS) g.truncated = true;
    for (const el of node.slice(0, MAX_ARRAY_OBJECTS)) if (isObj(el)) walk(g, el, depth + 1, parent, budget);
    return;
  }
  const p = leafNorm(parent);
  if ((node.enabled === false || node.enable === false) && TOGGLE_CONTAINER.test(p)) return;
  collectRule(g, node);
  if (depth === 0 && Array.isArray(node.allow) && ['ask', 'exclude', 'deny'].some((s) => Array.isArray(node[s]))) addAll(g.allow, asList(node.allow));
  const inFs = FS_PARENT.test(p);
  const inNet = NET_PARENT.test(p);
  for (const [rawKey, value] of ordered(node)) {
    const kFull = norm(rawKey);
    const k = leafNorm(rawKey);

    if (k === 'deny' && p === 'permissions') addAll(g.deny, asList(value));
    if (k === 'ask' && p === 'permissions') addAll(g.ask, asList(value));
    if (k === 'disallowedtools') addAll(g.deny, asList(value));

    if (k === 'permission' && !(isObj(value) && 'type' in value)) collectPermissionMap(g, value);
    if (p === 'toolpermissions') collectToolPermissions(g, k, value);
    if (k === 'allowunixsockets') addAll(g.unixSockets, asList(value));
    if (k === 'mcpallowlist') addAll(g.mcpAllowlist, asList(value).filter((v) => /^\s*\*\s*(?::\s*\*)?\s*$/.test(v)));
    if (p === 'foldertrust' && k === 'enabled' && value === false) g.folderTrustDisabled = true;
    if (kFull === 'chattoolseditsautoapprove' && isObj(value)) addAll(g.fileSystem.write, Object.entries(value).filter(([, on]) => on === true).map(([glob]) => glob));
    if (k === 'type' && typeof value === 'string' && norm(value) === 'insecurenone') g.flags.type = 'insecure_none';
    if (ANYWHERE_FS_KEYS[k]) addAll(g.fileSystem[ANYWHERE_FS_KEYS[k]], asList(value));
    if (PATH_LIST_PARENTS[p] && /^(?:allowedpaths|allowpaths|paths)$/.test(k)) addAll(g.fileSystem[PATH_LIST_PARENTS[p]], asList(value));
    if (inFs && typeof value === 'string' && /^(?:read|write)$/i.test(value) && /[\\/~*]|^\.{1,2}$/.test(rawKey)) addAll(g.fileSystem[value.toLowerCase()], [rawKey]);
    if (inNet && k === 'default' && /^allow$/i.test(String(value))) addAll(g.network.outbound, ['*']);
    if (inNet && k === 'enabled' && value === true) g.flags.networkEnabled = true;

    if ((MODE_KEYS.has(k) || FULL_MODE_KEYS.has(kFull)) && typeof value === 'string' && (k !== 'mode' || GENERIC_MODE_VALUES.has(norm(value)))) takeMode(g, value);
    else if (k === 'enableallprojectmcpservers') {
      if (value === true) g.enableAllProjectMcpServers = true;
      else if (value === false && g.enableAllProjectMcpServers === null) g.enableAllProjectMcpServers = false;
    } else if (FLAG_KEY.test(kFull) || FLAG_KEY.test(k)) {
      const fv = flagValue(value);
      if (fv !== undefined && !(rawKey in g.flags)) g.flags[String(rawKey).slice(0, 60)] = fv;
    }

    if ((k === 'allow' && p === 'permissions') || k === 'allowedtools' || (k === 'allowed' && p === 'tools')) addAll(g.allow, asList(value));

    if (FS_PARENT.test(p) && FS_KEYS[k]) addAll(g.fileSystem[FS_KEYS[k]], value === true ? ['/**'] : asList(value));
    else if (/^(?:readpaths|writepaths|executepaths|allowread|allowwrite|allowexecute)$/.test(k)) addAll(g.fileSystem[FS_KEYS[k]], asList(value));

    const listy = Array.isArray(value) || typeof value === 'string' || value === true;
    if (NET_PARENT.test(p) && OUTBOUND_KEYS.test(k)) addAll(g.network.outbound, value === true ? ['*'] : asList(value));
    else if (NET_PARENT.test(p) && INBOUND_KEYS.test(k)) addAll(g.network.inbound, value === true ? ['*'] : asList(value));
    else if (listy && /^(?:egress|outbound|alloweddomains|networkallowlist|allowedurls)$/.test(k)) addAll(g.network.outbound, asList(value));
    else if (listy && /^(?:inbound|ingress)$/.test(k)) addAll(g.network.inbound, asList(value));

    if (ENV_PARENT.test(p) && ENV_LIST_KEYS.test(k)) addAll(g.envNames, asList(value).filter((n) => /^(?:\*+|[A-Za-z_][A-Za-z0-9_]*\*?)$/.test(n.trim())));

    if ((TOOLS_PARENT.test(p) && (p === 'tools' ? TOOLS_EXEC_KEYS : EXEC_LIST_KEYS).test(k)) || COMMAND_LIST_KEYS.test(k) || COMMAND_LIST_KEYS.test(kFull)) addAll(g.commands, asList(value));

    if (DIRECTORY_KEYS.test(k)) addAll(g.directories, asList(value));
    if (TRUST_KEYS.test(k)) addAll(g.trustedFolders, asList(value));
    if (k === 'projects' && isObj(value)) {
      addAll(g.trustedFolders, Object.entries(value).filter(([, v]) => norm(v?.trust_level ?? v?.trustLevel ?? '') === 'trusted').map(([path]) => path));
    }

    if (value && typeof value === 'object' && !SKIP_SUBTREES.has(k)) {
      if (isObj(value) && (kFull === 'chattoolsterminalautoapprove' || kFull === 'terminalautoapprove')) {
        const wild = Object.entries(value).find(([cmd, on]) => on === true && /^(?:\*+|\/\.\*\/[a-z]*|\.\*)$/.test(cmd.trim()));
        if (wild && !(rawKey in g.flags)) g.flags[String(rawKey).slice(0, 60)] = ['*'];
        continue;
      }
      walk(g, value, depth + 1, rawKey, budget);
    }
  }
}

export function extractGrant(doc, into = emptyGrant()) {
  if (!isObj(doc)) return into;
  if (!findSettingsNode(doc) && !isObj(doc.projects)) return into;
  walk(into, doc, 0, '', { n: 0 });
  return into;
}

export function grantIsEmpty(g) {
  return !g || (
    !g.mode && !g.allow.length && !g.deny.length && !g.ask.length && !Object.keys(g.flags).length &&
    !g.fileSystem.read.length && !g.fileSystem.write.length && !g.fileSystem.execute.length &&
    !g.network.outbound.length && !g.network.inbound.length && !g.envNames.length && !g.commands.length &&
    !g.rules.length && !g.permission && !g.toolPermissions && !g.unixSockets.length && !g.mcpAllowlist.length && !g.folderTrustDisabled &&
    !g.directories.length && !g.trustedFolders.length && g.enableAllProjectMcpServers !== true
  );
}

function scanJson(raw, onChar) {
  let out = '';
  let inStr = false;
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (inStr) {
      out += c;
      if (c === '\\') out += raw[++i] ?? '';
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; out += c; continue; }
    const r = onChar(raw, i);
    if (r === undefined) out += c;
    else { out += r.emit; i = r.next; }
  }
  return out;
}

export function stripJsonc(raw) {
  const noComments = scanJson(String(raw).replace(/^﻿/, ''), (s, i) => {
    if (s[i] === '/' && s[i + 1] === '/') {
      let j = i;
      while (j < s.length && s[j] !== '\n') j++;
      return { emit: '\n', next: j };
    }
    if (s[i] === '/' && s[i + 1] === '*') {
      const end = s.indexOf('*/', i + 2);
      return { emit: ' ', next: end === -1 ? s.length : end + 1 };
    }
    return undefined;
  });
  return scanJson(noComments, (s, i) => {
    if (s[i] !== ',') return undefined;
    let j = i + 1;
    while (j < s.length && /\s/.test(s[j])) j++;
    return s[j] === '}' || s[j] === ']' ? { emit: '', next: i } : undefined;
  });
}

function yamlScalar(raw) {
  const hash = raw.search(/\s#/);
  const v = (hash === -1 ? raw : raw.slice(0, hash)).trim();
  if (/^(?:true|yes|on)$/i.test(v)) return true;
  if (/^(?:false|no|off)$/i.test(v)) return false;
  if (v === 'null' || v === '~' || v === '') return null;
  if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
  if (/^\[.*\]$/.test(v)) return v.slice(1, -1).split(',').map((t) => yamlScalar(t)).filter((t) => t !== null);
  return v.replace(/^(["'])(.*)\1$/, '$2');
}

export function parseLooseYaml(text) {
  if (typeof text !== 'string' || text.length > 512 * 1024) return null;
  const root = {};
  const stack = [{ indent: -1, node: root }];
  let pending = null;
  let sawAny = false;
  for (const rawLine of text.split(/\r?\n/)) {
    if (!rawLine.trim() || /^\s*#/.test(rawLine) || /^\s*---\s*$/.test(rawLine)) continue;
    const indent = rawLine.length - rawLine.trimStart().length;
    const line = rawLine.trim();
    const item = /^-\s*(.*)$/.exec(line);
    if (pending && (indent > pending.indent || (item && indent >= pending.indent))) {
      const node = item ? [] : {};
      pending.parent[pending.key] = node;
      stack.push({ indent: pending.indent, node });
    }
    pending = null;
    while (stack.length > 1 && indent <= stack[stack.length - 1].indent && !(item && Array.isArray(stack[stack.length - 1].node) && indent === stack[stack.length - 1].indent)) stack.pop();
    const frame = stack[stack.length - 1];
    if (item) {
      if (!Array.isArray(frame.node)) continue;
      sawAny = true;
      const inner = /^["']?([^:"'\s][^:"']*)["']?\s*:\s*(.*)$/.exec(item[1]);
      if (inner && !/^\w+\(/.test(item[1])) {
        const obj = {};
        frame.node.push(obj);
        stack.push({ indent: indent + 1, node: obj });
        if (inner[2]) obj[inner[1].trim()] = yamlScalar(inner[2]);
        else pending = { parent: obj, key: inner[1].trim(), indent: indent + 1 };
      } else if (item[1]) frame.node.push(yamlScalar(item[1]));
      continue;
    }
    const kv = /^["']?([^:"'][^:"']*?)["']?\s*:(?:\s+(.*)|\s*)$/.exec(line);
    if (!kv || Array.isArray(frame.node)) continue;
    sawAny = true;
    const key = kv[1].trim();
    const rest = (kv[2] ?? '').trim();
    if (!rest) {
      frame.node[key] = null;
      pending = { parent: frame.node, key, indent };
    } else frame.node[key] = yamlScalar(rest);
  }
  return sawAny ? root : null;
}

function tomlValue(raw) {
  const v = raw.trim();
  if (/^(true|false)$/.test(v)) return v === 'true';
  if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
  if (/^"(?:[^"\\]|\\.)*"$/.test(v)) {
    try { return JSON.parse(v); } catch { return v.slice(1, -1); }
  }
  if (/^'[^']*'$/.test(v)) return v.slice(1, -1);
  if (v.startsWith('[')) {
    const out = [];
    for (const m of v.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g)) out.push(m[1] !== undefined ? m[1] : m[2]);
    return out;
  }
  return undefined;
}

function tomlKey(raw) {
  const parts = [];
  for (const m of raw.trim().matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'|([^.\s"']+)/g)) parts.push(m[1] ?? m[2] ?? m[3]);
  return parts;
}

export function parseLooseToml(text) {
  if (typeof text !== 'string' || text.length > 512 * 1024) return null;
  const root = {};
  let cur = root;
  let pending = null;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].replace(/(^|\s)#.*$/, '').trim();
    if (!line) continue;
    const section = /^\[\[?\s*(.+?)\s*\]\]?$/.exec(line);
    if (section && !line.includes('=')) {
      cur = root;
      for (const k of tomlKey(section[1])) cur = isObj(cur[k]) ? cur[k] : (cur[k] = {});
      continue;
    }
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const keys = tomlKey(line.slice(0, eq));
    let rhs = line.slice(eq + 1).trim();
    if (rhs.startsWith('[') && !rhs.includes(']')) {
      while (++i < lines.length && !rhs.includes(']')) rhs += ' ' + lines[i].replace(/(^|\s)#.*$/, '').trim();
    }
    pending = cur;
    for (const k of keys.slice(0, -1)) pending = isObj(pending[k]) ? pending[k] : (pending[k] = {});
    const val = tomlValue(rhs);
    if (val !== undefined && keys.length) pending[keys[keys.length - 1]] = val;
  }
  return root;
}
