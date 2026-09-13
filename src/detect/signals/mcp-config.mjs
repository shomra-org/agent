import { assessUrl } from './egress.mjs';
import { MALICIOUS_PACKAGE_SEED, POPULAR_PACKAGES, editDistance } from './packages.mjs';
import { SECRET_PATTERNS, isPlaceholderSecret } from './secrets.mjs';
import { parseLooseToml } from '../../inventory/grant-extract.mjs';
import { parseYaml } from '../../core/yaml-lite.mjs';

const MAX_SERVERS = 200;
const MAX_ARGS = 64;
const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v) => (typeof v === 'string' && v.trim() ? v : null);
const strList = (v) => (Array.isArray(v) ? v.filter((x) => x != null && typeof x !== 'object').map(String).slice(0, MAX_ARGS) : []);

/* ─── documents ──────────────────────────────────────────────────────────── */

function stripJsonComments(s) {
  return String(s).replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:"])\/\/.*$/gm, '$1').replace(/,(\s*[}\]])/g, '$1');
}

export function parseConfigDoc(text, path = '') {
  if (typeof text !== 'string' || !text.trim()) return null;
  if (/\.toml$/i.test(path)) return parseLooseToml(text);
  if (/\.ya?ml$/i.test(path)) return parseYaml(text);
  try { return JSON.parse(stripJsonComments(text)); } catch { /* fall through */ }
  if (/^\s*\[/m.test(text) && /=/.test(text)) return parseLooseToml(text);
  return null;
}


const looksLikeServer = (v) => isObj(v) && ['command', 'cmd', 'url', 'httpUrl', 'serverUrl', 'uri', 'type', 'args'].some((k) => k in v);

function asMap(v) {
  if (isObj(v)) return v;
  if (Array.isArray(v) && v.some((x) => isObj(x) && typeof x.name === 'string')) {
    const out = {};
    for (const x of v.slice(0, MAX_SERVERS)) if (isObj(x) && typeof x.name === 'string') out[x.name] = x;
    return out;
  }
  return null;
}

export function findMcpServerMap(json) {
  if (!isObj(json)) return null;
  let found = asMap(json.mcpServers ?? json.servers ?? json.context_servers ?? json.contextServers ?? json.mcp_servers ?? json.mcp_server ?? json['mcp.servers']);
  if (!found) {
    const ext = json.extensions;
    if (isObj(ext) && Object.values(ext).some((v) => isObj(v) && (v.cmd || v.command || v.uri || v.url || v.type))) found = ext;
  }
  if (!found) {
    for (const key of ['mcp', 'mcpConfig', 'modelContextProtocol', 'mcp_config']) {
      const nested = json[key];
      if (!isObj(nested)) continue;
      const inner = asMap(nested.servers ?? nested.mcpServers ?? nested.context_servers ?? nested.mcp_servers);
      if (inner) { found = inner; break; }
      if (Object.values(nested).some(looksLikeServer)) { found = nested; break; }
    }
  }
  if (isObj(json.projects)) {
    const merged = { ...(found ?? {}) };
    let added = 0;
    for (const [projectPath, proj] of Object.entries(json.projects).slice(0, MAX_SERVERS)) {
      const m = isObj(proj) ? asMap(proj.mcpServers) : null;
      if (!m) continue;
      for (const [name, entry] of Object.entries(m)) {
        if (!isObj(entry)) continue;
        const base = projectPath.replace(/\\/g, '/').split('/').filter(Boolean).pop() || projectPath;
        merged[name in merged ? `${name} (${base})` : name] = { ...entry, __scope: projectPath };
        added++;
      }
    }
    if (added) found = merged;
  }
  return found && Object.keys(found).length ? found : null;
}

export function normalizeServerEntry(name, e) {
  const entry = isObj(e) ? e : {};
  let command = null;
  let args = strList(entry.args);
  let env = null;
  const rawCmd = entry.command ?? entry.cmd ?? entry.executable ?? null;
  if (typeof rawCmd === 'string') command = rawCmd;
  else if (Array.isArray(rawCmd)) {
    const argv = strList(rawCmd);
    command = argv[0] ?? null;
    args = [...argv.slice(1), ...args].slice(0, MAX_ARGS);
  } else if (isObj(rawCmd)) {
    command = str(rawCmd.path) ?? str(rawCmd.command);
    args = [...strList(rawCmd.args), ...args].slice(0, MAX_ARGS);
    if (isObj(rawCmd.env)) env = rawCmd.env;
  }
  for (const k of ['env', 'envs', 'environment']) if (isObj(entry[k])) env = { ...(env ?? {}), ...entry[k] };
  let headers = null;
  for (const k of ['headers', 'http_headers', 'httpHeaders']) if (isObj(entry[k])) headers = { ...(headers ?? {}), ...entry[k] };
  const url = str(entry.url) ?? str(entry.httpUrl) ?? str(entry.serverUrl) ?? str(entry.endpoint) ?? str(entry.uri);

  const approve = [];
  for (const k of ['alwaysAllow', 'autoApprove', 'autoApproveTools', 'auto_approve']) {
    const v = entry[k];
    if (v === true) approve.push('*');
    else approve.push(...strList(v));
  }
  const AUTO_MODE = /^(?:auto|approve|always|never[-_]?ask)$/i;
  if (typeof entry.default_tools_approval_mode === 'string' && AUTO_MODE.test(entry.default_tools_approval_mode)) approve.push('*');
  if (isObj(entry.tools)) {
    for (const [tool, cfg] of Object.entries(entry.tools).slice(0, 100)) if (isObj(cfg) && typeof cfg.approval_mode === 'string' && AUTO_MODE.test(cfg.approval_mode)) approve.push(tool);
  }
  const headersHelper = str(entry.headersHelper);
  return {
    name,
    command,
    args,
    env,
    headers,
    url,
    type: str(entry.type) ?? str(entry.transport) ?? str(entry.transportType),
    cwd: str(entry.cwd) ?? str(entry.working_directory) ?? str(entry.workingDirectory),
    envFile: str(entry.envFile) ?? str(entry.env_file),
    headersHelper,
    autoApprove: approve.length ? [...new Set(approve)].slice(0, 40) : null,
    trusted: entry.trust === true || entry.trusted === true,
    disabled: entry.disabled === true || entry.enabled === false,
    authDeclared: !!(entry.oauth || entry.auth || entry.authProviderType || entry.bearer_token_env_var || entry.bearerTokenEnvVar || isObj(entry.env_http_headers) || headersHelper || entry.authDeclared === true),
    scope: str(entry.__scope) ?? str(entry.scope),
  };
}


export function extensionBundleServer(json) {
  if (!isObj(json) || !isObj(json.server)) return null;
  const cfg = json.server.mcp_config ?? json.server.mcpConfig;
  const declared = typeof json.dxt_version === 'string' || typeof json.mcpb_version === 'string' || typeof json.manifest_version === 'string';
  if (!isObj(cfg) || (!declared && !json.server.entry_point)) return null;
  return normalizeServerEntry(String(json.name || json.display_name || 'extension'), cfg);
}

export function readMcpServers(json) {
  const map = findMcpServerMap(json);
  if (!map) {
    const ext = extensionBundleServer(json);
    return ext ? [ext] : null;
  }
  return Object.entries(map).slice(0, MAX_SERVERS).map(([name, entry]) => normalizeServerEntry(name, entry));
}

/* ─── launch parsing (launch-spec.ts) ────────────────────────────────────── */

const NPM_RUNNERS = new Set(['npx', 'npm', 'pnpm', 'yarn', 'bunx', 'bun']);
const PY_RUNNERS = new Set(['uvx', 'uv', 'pipx', 'pip', 'pip3', 'python', 'python3', 'poetry', 'pdm', 'hatch']);
const LAUNCH_SKIP = new Set(['exec', 'dlx', 'run', 'runx', 'install', 'add', 'create', 'tool', '-y', '--yes', '-m', '--from', '--with', '--quiet', '-q']);
const REGISTRY_FLAGS = /^(?:--registry|--index-url|-i|--extra-index-url|--default-index|--index)$/;

function registryOverride(tokens) {
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i];
    const eq = t.indexOf('=');
    const flag = eq > 0 ? t.slice(0, eq) : t;
    if (!REGISTRY_FLAGS.test(flag)) continue;
    const url = eq > 0 ? t.slice(eq + 1) : tokens[i + 1] ?? '';
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) continue;
    return { flag, url, plaintext: /^http:\/\//i.test(url), extra: flag === '--extra-index-url' || flag === '--index' };
  }
  return null;
}

function nonRegistrySource(spec, tokens, ecosystem) {
  const all = [spec, ...tokens];
  const shorthand = ecosystem === 'npm' && /^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9_.-]+(?:#.*)?$/.test(spec) && !/\.(?:[cm]?[jt]s|py|json|sh)$/i.test(spec);
  const hit = all.find((t) => /^(?:git\+|git:\/\/|github:|gitlab:|bitbucket:|gist:)/i.test(t)) ?? (shorthand ? spec : null);
  if (hit) return { kind: 'git', ref: hit, commitPinned: /[#@][0-9a-f]{40}\b/i.test(hit) };
  const url = all.find((t) => /^https?:\/\/\S+\.(?:tgz|tar\.gz|tar|zip|whl)(?:[?#]\S*)?$/i.test(t));
  if (url) return { kind: 'url', ref: url, commitPinned: false };
  const file = all.find((t) => /^file:/i.test(t));
  if (file) return { kind: 'file', ref: file, commitPinned: false };
  return null;
}

/** `C:\\Program Files\\nodejs\\npx.cmd` is npx - strip the Windows launcher extension (launch-spec.ts programName) */
export function programName(command) {
  const base = String(command ?? '').trim().split(/[\\/]/).pop() ?? '';
  return base.toLowerCase().replace(/\.(?:exe|cmd|bat|ps1)$/, '');
}

export function parseLaunch(command, args) {
  const tokens = [command, ...(args ?? [])].filter(Boolean).map(String);
  const none = { ecosystem: null, runner: null, pkg: null, spec: null, version: null, autoInstall: false, unpinned: false, source: null, registry: null };
  if (!tokens.length) return none;
  const head = programName(tokens[0]);
  const ecosystem = NPM_RUNNERS.has(head) ? 'npm' : PY_RUNNERS.has(head) ? 'python' : null;
  if (!ecosystem) return none;
  const autoInstall = tokens.some((t) => /^--?(y|yes)$/i.test(t)) || tokens.includes('dlx') || (ecosystem === 'python' && (head === 'uvx' || head === 'pipx' || tokens.includes('--from')));
  const registry = registryOverride(tokens);
  let spec = null;
  for (let i = 1; i < tokens.length && ecosystem === 'npm'; i++) {
    const t = tokens[i];
    if (t.startsWith('--package=')) { spec = t.slice('--package='.length); break; }
    if ((t === '--package' || t === '-p') && tokens[i + 1] && !tokens[i + 1].startsWith('-')) { spec = tokens[i + 1]; break; }
  }
  for (let i = 1; i < tokens.length && !spec; i++) {
    const t = tokens[i];
    if (t.startsWith('-') || LAUNCH_SKIP.has(t)) continue;
    if (registry && t === registry.url) continue;
    spec = t;
    break;
  }
  if (!spec) return { ...none, ecosystem, runner: head, autoInstall, registry };
  const source = nonRegistrySource(spec, tokens.slice(1), ecosystem);
  if (source) return { ecosystem, runner: head, pkg: spec, spec, version: null, autoInstall, unpinned: !source.commitPinned, source, registry };
  let pkg;
  let version;
  if (ecosystem === 'npm') {
    const at = spec.lastIndexOf('@');
    version = at > 0 ? spec.slice(at + 1) : null;
    pkg = spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/').replace(/@[\d^~].*$/, '') : spec.split('@')[0];
  } else {
    const m = /^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*(?:([=<>!~]+)\s*(.+))?$/.exec(spec);
    pkg = m ? m[1] : spec;
    version = m && m[2] === '==' ? (m[3] ?? null) : null;
  }
  const unpinned = !version || /^(latest|next|canary|\*|x|main|master)$/i.test(version) || !/^[~^]?\d/.test(version);
  return { ecosystem, runner: head, pkg: pkg || null, spec, version, autoInstall, unpinned, source: null, registry };
}

const SHELLS = /^(?:sh|bash|zsh|dash|ksh|fish|cmd|powershell|pwsh)(?:\.exe)?$/i;
const SCRIPT_META = /[;&|`<>\n]|\$\(|\$\{?[A-Za-z_]|%[A-Za-z_]\w*%/;
const splitWords = (s) => [...s.matchAll(/"([^"]*)"|'([^']*)'|(\S+)/g)].map((m) => m[1] ?? m[2] ?? m[3]);

export function unwrapShell(command, args) {
  const raw = String(command ?? '').trim();
  if (!raw) return null;
  let toks = (args ?? []).map(String);
  let head = raw;
  if (/\s/.test(raw) && !/^[a-z]:\\[^"]*\\[^\\]*$/i.test(raw)) {
    const words = splitWords(raw);
    head = words[0] ?? raw;
    toks = [...words.slice(1), ...toks];
  }
  const shell = (head.split(/[\\/]/).pop() ?? head).toLowerCase();
  if (!SHELLS.test(shell)) return null;
  const isCmd = /^cmd(\.exe)?$/.test(shell);
  const isPwsh = /^(powershell|pwsh)(\.exe)?$/.test(shell);
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    const inline = isCmd ? /^\/[ck]$/i.test(t) : isPwsh ? /^-(?:c|command)$/i.test(t) : /^-[a-z]*c[a-z]*$/i.test(t);
    const encoded = isPwsh && /^-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)$/i.test(t);
    if (!inline && !encoded) continue;
    const rest = toks.slice(i + 1);
    const script = (isCmd || isPwsh ? rest.join(' ') : rest[0] ?? '').trim();
    const compound = !encoded && SCRIPT_META.test(script);
    const words = !encoded && !compound ? splitWords(script) : [];
    return { shell, flag: t, script: script.slice(0, 400), encoded, compound, inner: words.length ? { command: words[0], args: words.slice(1) } : null };
  }
  return null;
}

export function launchPull(command, args) {
  const wrap = unwrapShell(command, args);
  const launch = wrap?.inner ? parseLaunch(wrap.inner.command, wrap.inner.args) : parseLaunch(command, (args ?? []).map(String));
  if (!launch.pkg || launch.source || !launch.ecosystem) return null;
  const version = !launch.unpinned && launch.version ? launch.version.replace(/^[~^=v]+/, '') : null;
  return { ecosystem: launch.ecosystem === 'python' ? 'pypi' : 'npm', name: launch.pkg, version };
}

const EVAL_FLAGS = [
  [/^(?:node|nodejs|bun)(?:\.exe)?$/i, /^(?:-e|--eval|-p|--print)$/],
  [/^deno(?:\.exe)?$/i, /^eval$/],
  [/^(?:python[\d.]*|py)(?:\.exe)?$/i, /^-c$/],
  [/^(?:ruby|perl)(?:\.exe)?$/i, /^-[eE]$/],
  [/^php(?:\.exe)?$/i, /^-r$/],
  [/^osascript$/i, /^-e$/],
];

function inlineEval(command, args) {
  const interpreter = programName(command);
  const pair = EVAL_FLAGS.find(([re]) => re.test(interpreter));
  if (!pair) return null;
  const toks = (args ?? []).map(String);
  const i = toks.findIndex((t) => pair[1].test(t));
  return i === -1 ? null : { interpreter, flag: toks[i] };
}

export function classifyScope(rawArg) {
  const raw = String(rawArg ?? '').trim().replace(/^["']|["']$/g, '');
  if (!raw) return null;
  const slashed = raw.replace(/\\/g, '/').replace(/^(?:\$\{?HOME\}?|%USERPROFILE%|\$\{?USERPROFILE\}?|\$env:USERPROFILE)(?=\/|$)/i, '~');
  if (!(/^([a-zA-Z]:)?\//.test(slashed) || /^~/.test(slashed))) return null;
  const p = (slashed.replace(/^[a-zA-Z]:/, '') || '/').replace(/(.)\/{1,256}$/, '$1');
  const norm = p.toLowerCase();
  if (norm === '' || norm === '/' || /^\/(mnt|media)$/.test(norm)) return { raw, label: 'the filesystem root', severity: 'CRITICAL' };
  if (/^~$/.test(p) || /^\/(users|home)\/[^/]+$/.test(norm) || /^\/root$/.test(norm)) return { raw, label: 'a user home directory', severity: 'HIGH' };
  if (/^\/(etc|var|usr|bin|sbin|boot|sys|proc|windows|program files.*)$/.test(norm)) return { raw, label: `a system directory (${raw})`, severity: 'HIGH' };
  if (/(^|\/)\.(ssh|aws|gnupg|kube|docker|config|azure|gcloud)$/.test(norm)) return { raw, label: `a credential directory (${raw})`, severity: 'CRITICAL' };
  return null;
}

const MOUNTABLE_MCP_PACKAGES = /(server-)?filesystem|mcp-fs|@modelcontextprotocol\/server-filesystem|mcp-server-file/i;
const SCOPE_FLAG_RE = /^--?(?:repository|repo|root|roots|allowed[-_]?(?:dirs?|directories|paths?|roots?)|dirs?|directory|workspace(?:[-_]?(?:root|dir))?|base[-_]?(?:dir|path)|path|project[-_]?(?:root|dir)|mount|sandbox[-_]?root)$/i;
const SCOPE_ENV_RE = /(?:ALLOWED|ROOT|WORKSPACE|MOUNT|SANDBOX|BASE|PROJECT)[_-]?(?:DIRS?|DIRECTOR(?:Y|IES)|PATHS?|ROOTS?|FOLDERS?)?$/i;
const SCOPE_ENV_NOUN = /DIR|PATH|ROOT|FOLDER|WORKSPACE|MOUNT/i;

/* ─── known-vulnerable.ts ────────────────────────────────────────────────── */

export const KNOWN_VULNERABLE_MCP = [
  { ecosystem: 'npm', pkg: 'mcp-remote', ranges: [{ from: '0.0.5', fixed: '0.1.16' }], cve: 'CVE-2025-6514', severity: 'CRITICAL' },
  { ecosystem: 'npm', pkg: '@modelcontextprotocol/inspector', ranges: [{ fixed: '0.14.1' }], cve: 'CVE-2025-49596', severity: 'CRITICAL' },
  { ecosystem: 'npm', pkg: '@modelcontextprotocol/server-filesystem', ranges: [{ fixed: '0.6.3' }, { from: '2025.0.0', fixed: '2025.7.1' }], cve: 'CVE-2025-53109 / CVE-2025-53110', severity: 'HIGH' },
  { ecosystem: 'python', pkg: 'mcp-server-git', ranges: [{ fixed: '2025.12.18' }], cve: 'CVE-2025-68143 / CVE-2025-68144 / CVE-2025-68145', severity: 'HIGH' },
];
const vparts = (v) => v.replace(/^[v=~^]+/, '').split(/[.+-]/).map((p) => (/^\d+$/.test(p) ? Number(p) : NaN)).filter((n) => !Number.isNaN(n));
function versionLt(a, b) {
  const x = vparts(a), y = vparts(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] ?? 0) - (y[i] ?? 0); if (d) return d < 0; }
  return false;
}
export function knownVulnerable(ecosystem, pkg, version) {
  if (!ecosystem || !pkg || !version || !/^[v=]?\d/.test(version)) return null;
  return KNOWN_VULNERABLE_MCP.find((k) => k.ecosystem === ecosystem && k.pkg === pkg.toLowerCase() &&
    k.ranges.some((r) => (!r.from || !versionLt(version, r.from)) && versionLt(version, r.fixed))) ?? null;
}

/* ─── the rules (launch-surface.ts) ──────────────────────────────────────── */

const REFERENCE_RE = /\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^}]*\}\}|%[A-Za-z_][A-Za-z0-9_]*%|^<[^>]+>$|^(?:op|vault|secret|keychain|azurekeyvault|gcpsm|aws-sm):\/\//i;
const DEFAULT_IN_REF_RE = /\$\{[A-Za-z_]\w*:-([^}]+)\}/;
const SECRET_KEY_RE = /\b(\w*(?:secret|token|passw(?:or)?d|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|auth[_-]?token|private[_-]?key|credential|session[_-]?key|encryption[_-]?key|signing[_-]?key)\w*)\b/i;
const HEADER_CRED_KEY_RE = /^(?:authorization|proxy-authorization|x-api-key|api-key|x-auth-token|x-access-token|cookie|x-goog-api-key)$/i;
const NOT_A_CREDENTIAL_KEY_RE = /(?:_|-|^)(?:URL|URI|ENDPOINT|HOST|PATH|FILE|DIR|NAME|TYPE|MODE|TTL|EXPIRY|EXPIRES|EXPIRATION|LENGTH|HEADER|ENV[_-]?VAR|VAR|ID|REGION|SCOPE|SCOPES|LIMIT|COUNT)$/i;
const PASSWORD_KEY_RE = /passw(?:or)?d|passwd|pwd|passphrase/i;
const URL_CRED_PARAM_RE = /^(?:api[-_]?key|apikey|key|token|access[-_]?token|auth[-_]?token|auth|secret|client[-_]?secret|password|pwd|sig|signature|session|x-api-key)$/i;

function isPlaceholderValue(v) {
  const low = v.toLowerCase();
  if (/(your|my|the|some|placeholder|example|sample|dummy|test|fake|changeme|redacted|x{3,64}|\.\.\.|todo|replace|insert|here|value|token|secret|key)$/i.test(low)) return true;
  if (/^[x*.\-_0]+$/i.test(v) || /(.)\1{7,}/.test(v) || /^(?:abc|123|test|foo|bar|qwerty)/i.test(low)) return true;
  return /token[-_ ]?here|xxx+|0000+|1234567890/i.test(v);
}
function entropy(s) {
  const f = new Map();
  for (const c of s) f.set(c, (f.get(c) ?? 0) + 1);
  let bits = 0;
  for (const n of f.values()) { const p = n / s.length; bits -= p * Math.log2(p); }
  return bits;
}

const CRED_FLAG_RE = /^--?(?:api[-_]?key|apikey|token|access[-_]?token|auth[-_]?token|bearer[-_]?token|secret|client[-_]?secret|password|passwd|pat|github[-_]?token)$/i;

/** `--api-key <v>`, `docker -e KEY=<v>`, `--header "Authorization: Bearer <v>"` (launch-surface.ts argCredentials) */
export function argCredentials(args) {
  const out = {};
  const toks = (args ?? []).map(String);
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    const eq = t.indexOf('=');
    const flag = t.startsWith('-') && eq > 0 ? t.slice(0, eq) : t;
    const next = eq > 0 && t.startsWith('-') ? t.slice(eq + 1) : toks[i + 1] ?? '';
    if (CRED_FLAG_RE.test(flag)) out[`arg ${flag}`] = next;
    else if ((flag === '-e' || flag === '--env') && /^[A-Za-z_][\w]*=/.test(next)) out[next.slice(0, next.indexOf('='))] = next.slice(next.indexOf('=') + 1);
    else if (flag === '--header' || flag === '-H') { const m = /^\s*([\w-]+)\s*:\s*(.+)$/.exec(next); if (m) out[m[1]] = m[2]; }
  }
  return out;
}

function literalCredential(key, raw, header) {
  if (typeof raw !== 'string') return null;
  let v = raw.trim();
  const dflt = DEFAULT_IN_REF_RE.exec(v);
  if (dflt) v = dflt[1].trim();
  else if (REFERENCE_RE.test(v)) return null;
  v = v.replace(/^(?:bearer|basic|token|apikey)\s+/i, '');
  if (v.length < 8 || /^(?:true|false|yes|no|on|off|null|none|\d+)$/i.test(v)) return null;
  if (/^(?:[a-z]+:\/\/|\/|~|\.{1,2}\/|[a-z]:\\)/i.test(v) || /^[A-Z][A-Z0-9_]+$/.test(v)) return null;
  const credKey = header ? HEADER_CRED_KEY_RE.test(key) || SECRET_KEY_RE.test(key) : SECRET_KEY_RE.test(key);
  if (!credKey || NOT_A_CREDENTIAL_KEY_RE.test(key) || isPlaceholderSecret(v) || /token[-_ ]?here/i.test(v)) return null;
  if (header && HEADER_CRED_KEY_RE.test(key)) return v;
  if (isPlaceholderValue(v)) return null;
  if (PASSWORD_KEY_RE.test(key)) return v;
  if (v.length < 16) return null;
  return entropy(v) >= (/^[0-9a-f]+$/i.test(v) ? 3.0 : 3.3) ? v : null;
}

function urlCredential(raw) {
  let u;
  try { u = new URL(String(raw)); } catch { return null; }
  if (u.password && !REFERENCE_RE.test(decodeURIComponent(u.password)) && !isPlaceholderValue(u.password)) return 'the URL userinfo';
  for (const [k, v] of u.searchParams) if (URL_CRED_PARAM_RE.test(k) && v.length >= 8 && !REFERENCE_RE.test(v) && !isPlaceholderValue(v)) return `the "${k}" query parameter`;
  return null;
}

const DROP_DIR_RE =
  /^(?:\/tmp\/|\/var\/tmp\/|\/dev\/shm\/|\/private\/tmp\/|~\/(?:\.cache|Downloads)\/|\$\{?TMPDIR\}?\/|%TEMP%|%TMP%|\$env:TE?MP\/|[a-z]:\/users\/[^/]+\/(?:appdata\/local\/temp|downloads)\/|[a-z]:\/windows\/temp\/|%LOCALAPPDATA%\/temp\/|%USERPROFILE%\/downloads\/)/i;
const isDropPath = (v) => DROP_DIR_RE.test(String(v ?? '').replace(/\\/g, '/'));
const BRIDGE_PKG_RE = /^(?:mcp-remote|mcp-proxy|supergateway|@modelcontextprotocol\/proxy)$/i;
const INDIRECT_LAUNCHERS = /^(?:npx|npm|pnpm|yarn|bunx|uvx|uv|pipx|docker|podman|nerdctl)$/i;
const INTERPRETERS = /^(?:node|deno|bun|python[\d.]*|ruby|perl|php|sh|bash|zsh|dash|osascript|pwsh|powershell)$/i;
const RELATIVE_SCRIPT_RE = /^(?:\.{1,2}[\\/])?[\w.-]+(?:[\\/][\w.-]+)*\.(?:[cm]?js|ts|py|sh|rb|pl|php|ps1|bat|cmd|exe)$/i;
const WILDCARD_TOOL_RE = /^\s*(?:\*+|all|any|\.\*)\s*$/i;
const EXEC_TOOL_RE = /(?:^|[_\-.])(?:exec|execute|run|shell|bash|zsh|powershell|terminal|command|cmd|eval|script|spawn|process)(?:[_\-.]|$)|^(?:bash|shell|terminal|exec)$/i;
const WRITE_TOOL_RE = /(?:write|edit|create|delete|remove|rm|move|rename|push|commit|merge|deploy|send|post|publish|upload|drop|update|insert|kill|transfer|pay|apply|patch)/i;
const LOADER_ENV = /^(?:NODE_OPTIONS|LD_PRELOAD|DYLD_INSERT_LIBRARIES|PYTHONSTARTUP|BASH_ENV|PERL5OPT|RUBYOPT)$/;


export function gradeServer(s) {
  const out = [];
  const push = (severity, title, remediationText, anchor) => out.push({ severity, title, remediationText, anchor: anchor ?? s.name });
  const wrap = unwrapShell(s.command, s.args);
  const eff = wrap?.inner ? { ...s, command: wrap.inner.command, args: wrap.inner.args } : s;
  const cmdLine = [s.command, ...(s.args ?? [])].filter(Boolean).join(' ');

  // transport
  const u = assessUrlWs(s.url);
  if (u) {
    if (u.suspiciousHost) push('HIGH', `MCP server "${s.name}" is hosted on a data-exfiltration endpoint`, 'Remove this server and treat any credential in its config as compromised.', u.url);
    if (u.metadataEndpoint) push('CRITICAL', `MCP server "${s.name}" targets the cloud metadata endpoint`, 'Remove this server immediately and rotate the instance role credentials.', u.url);
    else if (u.privateNetwork) push('LOW', `MCP server "${s.name}" points at a private-network address`, 'Keep local-only servers out of committed configuration.', u.url);
    if (u.plaintext && !u.privateNetwork) push('MEDIUM', u.websocket ? `MCP server "${s.name}" uses an unencrypted WebSocket (ws://)` : `MCP server "${s.name}" uses plaintext HTTP`, 'Use an https:// (wss://) endpoint and require an authenticated token.', u.url);
    if (u.rawIp && !u.privateNetwork) push('LOW', `MCP server "${s.name}" is addressed by raw IP`, 'Use a DNS hostname with a valid TLS certificate.', u.url);
    if (!u.privateNetwork) {
      const keys = Object.keys({ ...(s.headers ?? {}), ...(s.env ?? {}) });
      const authish = keys.some((k) => /(^|[_-])(authorization|auth|token|key|secret|bearer|api[_-]?key|credential|password|cookie)/i.test(k));
      if (!authish && !s.authDeclared && !urlCredential(u.url)) push('MEDIUM', `Remote MCP server "${s.name}" declares no authentication`, 'Require an authenticated token and pass it through an environment reference.', u.url);
    }
  }

  if (!s.url) {
    const bridged = parseLaunch(eff.command, eff.args ?? []);
    const target = bridged.pkg && BRIDGE_PKG_RE.test(bridged.pkg) ? (eff.args ?? []).find((a) => /^(?:https?|wss?):\/\//i.test(String(a))) : null;
    if (target) for (const f of gradeServer({ name: s.name, url: target, headers: { ...(s.headers ?? {}), ...argCredentials(eff.args) } })) out.push(f);
  }

  // shells & inline code
  if (wrap) {
    const isCmd = /^cmd(\.exe)?$/.test(wrap.shell);
    if (wrap.encoded) push('HIGH', `MCP server "${s.name}" launches an encoded PowerShell command`, 'Replace the encoded command with the plain command it stands for.', wrap.flag);
    else if (/\$\{user_config\.[\w.-]+\}/.test(wrap.script)) push('HIGH', `MCP server "${s.name}" substitutes user configuration into a shell command line`, 'Pass the setting as its own argv entry or an environment variable the program reads - never inside a shell string.', wrap.flag);
    else if (wrap.compound) push('MEDIUM', `MCP server "${s.name}" is launched as a shell script`, 'Launch the server binary directly with its arguments as a list.', wrap.flag);
    else if (!isCmd && wrap.inner) push('LOW', `MCP server "${s.name}" is launched through ${wrap.shell}`, `Set "command" to "${wrap.inner.command}" and "args" to its arguments directly.`, wrap.flag);
  }
  const ev = inlineEval(s.command, s.args);
  if (ev) push('MEDIUM', `MCP server "${s.name}" runs inline code from its config`, 'Move the code into a checked-in file (or a pinned package) and launch that instead.', ev.flag);

  // tools the client runs without asking
  if (!s.disabled) {
    if (s.trusted) push('HIGH', `MCP server "${s.name}" is trusted - none of its tool calls ask first`, 'Remove "trust": true and allow-list the read-only tools that are safe to run unprompted.', /"?trust"?\s*[:=]\s*true/);
    const tools = s.autoApprove ?? [];
    const wildcard = tools.some((t) => WILDCARD_TOOL_RE.test(t));
    const exec = tools.filter((t) => EXEC_TOOL_RE.test(t));
    const write = tools.filter((t) => !EXEC_TOOL_RE.test(t) && WRITE_TOOL_RE.test(t));
    if (wildcard || exec.length || write.length) {
      push(wildcard || exec.length ? 'HIGH' : 'MEDIUM',
        `MCP server "${s.name}" auto-approves ${wildcard ? 'every tool' : exec.length ? 'command-running tools' : 'tools that change things'}`,
        'Keep only read-only tools on the auto-approve list; let the client ask for anything that writes, sends, deletes or runs a command.',
        wildcard ? tools.find((t) => WILDCARD_TOOL_RE.test(t)) : exec[0] ?? write[0]);
    }
  }

  // containers
  const cbase = programName(eff.command);
  if (['docker', 'podman', 'nerdctl'].includes(cbase)) {
    const joined = (eff.args ?? []).join(' ');
    const escapes = [];
    if (/(^|\s)--privileged(\s|=|$)/.test(joined)) escapes.push('--privileged');
    if (/docker\.sock/i.test(joined)) escapes.push('docker.sock');
    if (/(?:-v|--volume|--mount)[\s=](?:type=bind,)?(?:source=|src=)?(\/|~|\/etc|\/root|\/home|\$HOME)(?::|,|\s|$)/.test(joined)) escapes.push('host mount');
    if (/--(?:network|net|pid|ipc|uts)[\s=]host\b/.test(joined)) escapes.push('host namespace');
    if (escapes.length) push(escapes.some((e) => e !== 'host namespace') ? 'HIGH' : 'MEDIUM', `MCP server "${s.name}" runs a container with host-level access`, 'Drop --privileged and host mounts; never expose the Docker socket.', escapes[0] === 'docker.sock' ? 'docker.sock' : escapes[0]);
    const image = (eff.args ?? []).find((t, i, a) => !t.startsWith('-') && !['run', 'exec', 'create', 'start'].includes(t) && !/^-/.test(a[i - 1] ?? '') );
    if (image && !/@sha256:/.test(image)) {
      const tag = image.includes(':') ? image.slice(image.lastIndexOf(':') + 1) : null;
      if (!tag || /^(latest|main|master|dev|edge|nightly)$/i.test(tag)) push('LOW', `MCP server "${s.name}" runs an unpinned container image`, 'Pin the image by digest (image@sha256:…).', image);
    }
  }

  // credentials
  const envBlob = JSON.stringify(s.env ?? {}) + '\n' + JSON.stringify(s.headers ?? {}) + '\n' + String(s.url ?? '');
  let named = false;
  for (const { re } of SECRET_PATTERNS) {
    const m = re.exec(envBlob) ?? re.exec(cmdLine);
    if (!m || isPlaceholderSecret(m[0])) continue;
    push('CRITICAL', `Static credential in MCP server "${s.name}"`, 'Rotate the credential and pass it via an environment reference resolved at runtime.', re);
    named = true;
    break;
  }
  const lits = [];
  for (const [where, block] of [['env', s.env], ['headers', s.headers], ['args', argCredentials(s.args)]]) {
    for (const [k, v] of Object.entries(block ?? {})) {
      const lit = literalCredential(k, v, where !== 'env');
      if (lit && !SECRET_PATTERNS.some(({ re }) => re.test(lit))) lits.push(k);
    }
  }
  if (lits.length) push('HIGH', `MCP server "${s.name}" stores a credential as a literal in ${lits.length === 1 ? `"${lits[0]}"` : `${lits.length} fields`}`, 'Rotate the value and reference it ("${VAR}", "${env:VAR}", a VS Code password input, Codex bearer_token_env_var) instead of storing it.', lits[0]);
  for (const raw of [s.url, ...(s.args ?? [])].filter((x) => typeof x === 'string' && /^[a-z][a-z0-9+.-]*:\/\//i.test(x))) {
    if (named || SECRET_PATTERNS.some(({ re }) => re.test(raw)) || !urlCredential(raw)) continue;
    push('HIGH', `MCP server "${s.name}" carries a credential in its URL`, 'Move the credential into an Authorization header resolved from an environment reference, and rotate it.', raw.slice(0, 60));
    break;
  }
  for (const [k, v] of Object.entries(s.env ?? {})) {
    if (LOADER_ENV.test(k) && /(--require|-r\s|--import|--loader|\.so\b|\.dylib\b|[/\\])/.test(String(v))) {
      push(splitWords(String(v)).some((w) => isDropPath(w)) ? 'CRITICAL' : 'HIGH', `MCP server "${s.name}" is launched with an execution hook in its environment (${k})`, `Remove ${k} from the server's env block.`, k);
    }
  }

  // droppers
  if (s.envFile && isDropPath(s.envFile)) push('HIGH', `MCP server "${s.name}" loads its environment from a world-writable file`, 'Keep the env file next to the config, readable only by its owner.', s.envFile);
  const helper = String(s.headersHelper ?? '').trim();
  const helperPath = helper ? splitWords(helper).find((v) => isDropPath(v)) : null;
  if (helperPath) push('CRITICAL', `MCP server "${s.name}" runs a file from a world-writable directory`, 'Move the helper into the repository or a package the org controls.', helperPath);
  const command = String(eff.command ?? '').trim();
  if (command && !INDIRECT_LAUNCHERS.test(programName(command))) {
    const base = programName(command);
    const argv = (eff.args ?? []).filter((v) => !v.startsWith('-'));
    const candidates = INTERPRETERS.test(base) ? argv : [command, ...argv];
    let dropped = candidates.find((v) => isDropPath(v));
    const cwd = String(s.cwd ?? '').trim();
    if (!dropped && cwd && isDropPath(/[\\/]$/.test(cwd) ? cwd : cwd + '/')) {
      const rel = candidates.find((v) => RELATIVE_SCRIPT_RE.test(v));
      if (rel) {
        let end = cwd.length;
        while (end > 0 && (cwd[end - 1] === '/' || cwd[end - 1] === '\\')) end--;
        dropped = `${cwd.slice(0, end)}/${rel.replace(/^\.[\\/]/, '')}`;
      }
    }
    if (dropped && !helperPath) push('CRITICAL', `MCP server "${s.name}" runs a file from a world-writable directory`, 'Move the server into the repository or a package the org controls, and pin it.', dropped);
  }

  // what runs
  const launch = parseLaunch(eff.command, eff.args ?? []);
  const pkg = launch.pkg;
  const mounted = new Set();
  if (pkg) {
    const vuln = knownVulnerable(launch.ecosystem, pkg, launch.version);
    if (vuln) push(vuln.severity, `MCP server "${s.name}" is pinned to a vulnerable release of ${pkg} (${vuln.cve})`, `Upgrade "${pkg}" to ${vuln.ranges[vuln.ranges.length - 1].fixed} or later and pin that release.`, launch.spec);
    const r = launch.registry;
    if (r?.plaintext) push('HIGH', `MCP server "${s.name}" installs from a registry over plaintext HTTP`, 'Use an https:// registry.', r.url);
    else if (r?.extra) push('MEDIUM', `MCP server "${s.name}" resolves packages from an extra index (dependency confusion)`, 'Use a single index that proxies the public one, or pin an exact version and hash.', r.url);
    if (launch.source) {
      const src = launch.source;
      push(src.commitPinned ? 'LOW' : 'MEDIUM',
        src.commitPinned ? `MCP server "${s.name}" runs code from a git commit, not a registry` : `MCP server "${s.name}" runs code straight from ${src.kind === 'git' ? 'a git branch' : src.kind === 'url' ? 'a download URL' : 'a local path'}`,
        'Pin to a full commit SHA or, better, a published registry release pinned to an exact version.', src.ref);
    } else {
      if (MALICIOUS_PACKAGE_SEED.has(pkg)) push('CRITICAL', `MCP server "${s.name}" runs a known-malicious package`, 'Remove this server and audit for compromise.', pkg);
      else {
        const squat = POPULAR_PACKAGES.find((p) => p !== pkg && editDistance(pkg, p) === 1);
        if (squat) push('MEDIUM', `Possible typosquat in "${s.name}": ${pkg}`, `Confirm the intended package is "${squat}", not "${pkg}", and pin it.`, pkg);
      }
      if (launch.unpinned || launch.autoInstall) {
        push('LOW', launch.unpinned ? (launch.autoInstall ? `MCP server "${s.name}" auto-installs an unpinned package` : `MCP server "${s.name}" pulls an unpinned package`) : `MCP server "${s.name}" auto-installs a pinned package at launch`,
          launch.unpinned ? `Pin "${pkg}" to a reviewed version and vet upgrades before adopting them.` : 'Vendor the package or install it ahead of time if the launch-time fetch matters.', pkg);
      }
      if (MOUNTABLE_MCP_PACKAGES.test(pkg)) {
        for (const a of eff.args ?? []) {
          if (!a || a.startsWith('-') || a === pkg) continue;
          const scope = classifyScope(a);
          if (scope) { mounted.add(scope.raw); push(scope.severity, `MCP server "${s.name}" is mounted at ${scope.label}`, 'Mount the narrowest directory the task needs (e.g. the project folder).', scope.raw); }
        }
      }
    }
  }

  // scope spelled as a flag or env var
  const toks = (eff.args ?? []).map(String);
  const scopes = [];
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    const eq = t.indexOf('=');
    const flag = eq > 0 ? t.slice(0, eq) : t;
    if (!flag.startsWith('-') || !SCOPE_FLAG_RE.test(flag)) continue;
    for (const v of (eq > 0 ? t.slice(eq + 1) : toks[i + 1] ?? '').split(/[;,]/)) { const sc = classifyScope(v); if (sc) scopes.push({ ...sc, via: flag }); }
  }
  for (const [k, v] of Object.entries(s.env ?? {})) {
    if (typeof v !== 'string' || !SCOPE_ENV_RE.test(k) || !SCOPE_ENV_NOUN.test(k)) continue;
    for (const part of v.split(/[;,]|:(?=[/~])/)) { const sc = classifyScope(part); if (sc) scopes.push({ ...sc, via: k }); }
  }
  for (const sc of scopes) {
    if (mounted.has(sc.raw)) continue;
    mounted.add(sc.raw);
    push(sc.severity, `MCP server "${s.name}" is scoped to ${sc.label}`, `Point ${sc.via} at the narrowest directory the task needs, not "${sc.raw}".`, sc.raw);
  }
  return out;
}

function assessUrlWs(raw) {
  const s = String(raw ?? '').trim();
  if (!s) return null;
  const ws = /^wss?:\/\//i.test(s);
  const a = assessUrl(ws ? s.replace(/^ws/i, 'http') : s);
  if (!a) return null;
  return { ...a, url: s, websocket: ws };
}

/** Every finding a config document earns - the local gate's MCP half. */
export function gradeMcpDocument(content, path = '') {
  const doc = parseConfigDoc(content, path);
  const servers = doc ? readMcpServers(doc) : null;
  if (!servers) return { servers: null, findings: [] };
  const findings = [];
  for (const s of servers) for (const f of gradeServer(s)) findings.push({ ...f, server: s.name });
  return { servers, findings };
}
