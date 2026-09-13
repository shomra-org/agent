import { assessUrl } from './egress.mjs';
import { lineOf } from './lines.mjs';
import { gradeMcpDocument, parseConfigDoc } from './mcp-config.mjs';

export const PLUGIN_MANIFEST_RE =
  /(^|\/)(?:\.(?:claude|codex|cursor|copilot|github)-plugin|\.plugin|\.github\/plugin)\/(?:plugin|marketplace)\.json$|(^|\/)\.agents\/plugins\/marketplace\.json$|(^|\/)gemini-extension\.json$|(^|\/)openclaw\.plugin\.json$/i;

export const TOOL_MANIFEST_RE =
  /(^|\/)(?:ai-plugin|apiplugin|declarativeagent)\.json$|(^|\/)\.well-known\/(?:ai-plugin\.json|openapi\.(?:json|ya?ml))$|(^|\/)\.roomodes$/i;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v) => (typeof v === 'string' && v.trim() ? v.trim() : null);
const SHA_RE = /^[0-9a-f]{40}([0-9a-f]{24})?$/i;
const SEMVER_TAG_RE = /^v?\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/;
const RAW_CODE_HOST_RE = /\b(?:raw\.githubusercontent\.com|gist\.github(?:usercontent)?\.com|gitlab\.com\/[^\s]*\/-\/raw\/|bitbucket\.org\/[^\s]*\/raw\/)/i;
const SHELL_COMMAND_RE = /(^|[\\/])(sh|bash|dash|zsh|ksh|cmd|cmd\.exe|powershell|powershell\.exe|pwsh)$/i;
const SHELL_FLAG_RE = /^(-c|-Command|-EncodedCommand|\/c|\/k)$/i;
const SECRETISH_KEY_RE = /(^|[_-])(api[_-]?key|apikey|token|secret|password|passwd|credential|private[_-]?key|access[_-]?key|bearer|auth)/i;
const MUTATING_METHODS = new Set(['post', 'put', 'patch', 'delete']);
const MUTATING_VERB_RE = /\b(create|update|delete|remove|send|post|submit|transfer|pay|refund|approve|cancel|write|modify|publish|share|grant|revoke|purge|drop|charge|execute|deploy)\w*/i;

export const RESERVED_MARKETPLACE_NAMES = new Set([
  'claude-code-marketplace', 'claude-code-plugins', 'claude-plugins-official', 'claude-plugins-community',
  'claude-community', 'anthropic-marketplace', 'anthropic-plugins', 'agent-skills', 'anthropic-agent-skills',
  'knowledge-work-plugins', 'life-sciences', 'claude-for-legal', 'claude-for-financial-services',
  'financial-services-plugins', 'first-party-plugins', 'claude-tag-plugins', 'healthcare',
]);
const IMPERSONATION_NAME_RE = /anthropic|(?:official|verified|first[-_. ]?party)[-_. ]*claude|claude[-_. ]*(?:official|verified|first[-_. ]?party)|claude[-_. ]*plugins[-_. ]*(?:official|v\d)/i;

function parse(content, path) {
  const text = String(content ?? '').replace(/^﻿/, '');
  try {
    const doc = parseConfigDoc(text, path || 'x.json');
    if (doc) return doc;
  } catch {  }
  try { return parseConfigDoc(text.replace(/,(\s*[}\]])/g, '$1'), path || 'x.json'); } catch { return null; }
}

const CONFUSABLE = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's',
  'ԁ': 'd', 'һ': 'h', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w', 'ɡ': 'g', 'ο': 'o', 'α': 'a', 'ν': 'v', 'ι': 'i',
  'κ': 'k', 'τ': 't', 'υ': 'u', 'ρ': 'p', 'ε': 'e',
};
const INVISIBLE_RE = /[­͏؜ᅟᅠ឴឵᠎​-‏‪-‮⁠-⁤⁦-⁩ㅤ﻿ﾠ]/g;

export function nameSkeleton(name) {
  return String(name ?? '').normalize('NFKC').replace(INVISIBLE_RE, '').toLowerCase().replace(/[^\x00-\x7f]/g, (ch) => CONFUSABLE[ch] ?? ch);
}

function isDisguised(name) {
  const n = String(name ?? '');
  return /[­͏؜ᅟᅠ឴឵᠎​-‏‪-‮⁠-⁤⁦-⁩ㅤ﻿ﾠ]/.test(n) || (/[A-Za-z]/.test(n) && /[Ͱ-ϿЀ-ԯ]/.test(n));
}

export function normalizeSource(src) {
  if (typeof src === 'string') {
    const s = src.trim();
    if (!s) return null;
    if (/^https?:\/\//i.test(s)) {
      const hash = s.indexOf('#');
      const ref = hash > -1 ? s.slice(hash + 1) || null : null;
      return { type: 'url', raw: s, url: hash > -1 ? s.slice(0, hash) : s, ref, sha: ref && SHA_RE.test(ref) ? ref : (/\b([0-9a-f]{40})\b/i.exec(s)?.[1] ?? null) };
    }
    if (/^git@|^(?:git\+)?(?:ssh|git):\/\//i.test(s)) return { type: 'git', raw: s, url: s, ref: null, sha: null };
    return { type: 'relative', raw: s, path: s };
  }
  if (!isObj(src)) return null;
  const kind = String(src.source ?? src.type ?? '').toLowerCase();
  const ref = str(src.ref) ?? str(src.branch) ?? str(src.tag);
  const sha = [src.sha, src.commit].map(str).find((x) => x && SHA_RE.test(x)) ?? null;
  const url = str(src.url);
  if (kind === 'github' || (!kind && str(src.repo))) return { type: 'github', raw: `github:${src.repo}`, url: src.repo ? `https://github.com/${src.repo}` : null, ref, sha };
  if (kind === 'npm') return { type: 'npm', raw: `npm:${src.package}`, pkg: str(src.package), version: str(src.version) };
  if (kind === 'local' || kind === 'path' || kind === 'directory' || kind === 'file') return { type: 'relative', raw: str(src.path) ?? '?', path: str(src.path) };
  if (kind === 'archive') return { type: 'archive', raw: url ?? '?', url, digest: str(src.sha256) };
  if (kind === 'command') return { type: 'command', raw: `command:${str(src.command) ?? '?'}`, command: str(src.command) };
  return { type: url ? 'url' : 'unknown', raw: url ?? '?', url, ref, sha };
}

export function pinning(s) {
  if (s.type === 'relative' || s.type === 'command' || s.type === 'unknown') return null;
  if (s.type === 'archive') return s.digest ? 'pinned' : 'floating';
  if (s.type === 'npm') {
    const v = s.version ?? '';
    if (!v || /^(latest|\*|next)$/i.test(v)) return 'floating';
    return /^[\^~><=*]|\|\||\.x\b/.test(v) ? 'range' : 'pinned';
  }
  if (s.sha) return 'pinned';
  if (s.ref && SHA_RE.test(s.ref)) return 'pinned';
  if (s.url && /\/(?:releases\/download|archive\/refs\/tags)\//i.test(s.url)) return 'pinned';
  if (s.ref && SEMVER_TAG_RE.test(s.ref.replace(/^refs\/tags\//, ''))) return 'tag';
  return s.ref ? 'branch' : 'floating';
}

export function escapesRoot(p) {
  const s = String(p).replace(/\\/g, '/').replace(/\$\{?(?:CLAUDE_PLUGIN_ROOT|PLUGIN_ROOT|extensionPath)\}?/g, '.');
  if (/^(?:\/|~|[a-z]:\/|\$\{?HOME\}?|%\w+%)/i.test(s)) return true;
  let depth = 0;
  for (const seg of s.split('/')) {
    if (seg === '..') { if (--depth < 0) return true; } else if (seg && seg !== '.') depth++;
  }
  return false;
}

function runnerUnpinned(command, args) {
  const bin = String(command ?? '').replace(/\\/g, '/').split('/').pop().toLowerCase().replace(/\.(cmd|exe)$/, '');
  const eco = { npx: 'npm', bunx: 'npm', pnpx: 'npm', uvx: 'pip' }[bin];
  if (!eco) return null;
  const spec = (args ?? []).map(String).find((x) => !x.startsWith('-'));
  if (!spec) return null;
  const pinned = eco === 'npm' ? /^(@[^/]+\/)?[^@]+@\d+\.\d+\.\d+/.test(spec) : /==\d/.test(spec);
  return pinned ? null : spec;
}

export function localPlugin(content, { path } = {}) {
  const out = [];
  const push = (severity, title, remediationText, needle) => out.push({ severity, title, remediationText, ...(needle ? { line: lineOf(content, needle) } : {}) });
  const doc = parse(content, path);
  if (!isObj(doc)) return out;

  if (Array.isArray(doc.plugins)) {
    const name = nameSkeleton(String(doc.name ?? '').trim());
    const disguised = [doc.name, ...doc.plugins.map((p) => p?.name)].find((n) => typeof n === 'string' && isDisguised(n));
    if (disguised) push('HIGH', `Name "${nameSkeleton(disguised)}" is not what it looks like (invisible or look-alike characters)`, 'Reject the manifest until every name is plain ASCII.', disguised);
    if (doc.plugins.length > 5000) push('MEDIUM', `Marketplace lists ${doc.plugins.length} plugins - only the first 5000 were checked`, 'Review the entries past the cap by hand.');
    const claimsVendor = /@anthropic\.com$/i.test(String(doc.owner?.email ?? ''));
    if (name && !claimsVendor && (RESERVED_MARKETPLACE_NAMES.has(name) || IMPERSONATION_NAME_RE.test(name))) {
      push(RESERVED_MARKETPLACE_NAMES.has(name) ? 'HIGH' : 'MEDIUM', `Marketplace "${doc.name}" is named to look like the vendor's official catalogue`, 'Rename it to identify its real publisher.', String(doc.name));
    }
    for (const e of doc.plugins.slice(0, 5000)) {
      if (!isObj(e)) continue;
      const s = normalizeSource(e.source);
      const label = String(e.name ?? '?');
      if (s) {
        if (s.type === 'relative' && s.path && escapesRoot(s.path)) push('MEDIUM', `Marketplace entry "${label}" installs from outside the marketplace (${s.path})`, 'Keep relative sources inside the marketplace repository.', s.path);
        else if (s.type === 'command') push('MEDIUM', `Marketplace entry "${label}" is built by running a command on the installing machine`, 'Use a repository or archive source pinned by commit SHA / sha256.', 'command');
        else {
          const u = s.url ? assessUrl(s.url) : null;
          if (s.url && /^[a-z][\w+.-]*:\/\/[^/\s@]+:[^/\s@]+@/i.test(s.url)) push('HIGH', `Marketplace entry "${label}" embeds a credential in its source URL`, 'Rotate the token and remove it from the URL.', label);
          if (u?.metadataEndpoint) push('CRITICAL', `Marketplace entry "${label}" installs from the cloud metadata endpoint`, 'Remove the entry.', s.url);
          else if (u?.suspiciousHost) push('HIGH', `Marketplace entry "${label}" installs from an untrusted host (${u.suspiciousHost})`, 'Install plugins only from a reviewed source.', s.url);
          else if (u?.plaintext && !u.privateNetwork) push('MEDIUM', `Marketplace entry "${label}" installs over plaintext HTTP`, 'Use an https:// source.', s.url);
          const pin = pinning(s);
          if (s.url && RAW_CODE_HOST_RE.test(s.url) && pin !== 'pinned') push('HIGH', `Plugin "${label}" installs from an unpinned raw-file source`, 'Pin the source to a full commit SHA or a signed release.', s.url);
          else if (pin === 'floating' || pin === 'branch' || pin === 'range') push('MEDIUM', `Plugin "${label}" installs from an unpinned source (${s.raw})`, 'Add a `sha` with the full commit of the reviewed revision (or an exact version / sha256).', label);
        }
      }
      if (isObj(e.mcpServers)) {
        for (const f of gradeMcpDocument(JSON.stringify({ mcpServers: e.mcpServers }), 'marketplace.json').findings) push(f.severity, `${label}: ${f.title}`, f.remediationText, f.server);
      }
      if (isObj(e.lspServers)) out.push(...lspRows(e.lspServers, `Marketplace entry "${label}"`, content));
    }
    return out;
  }

  for (const key of ['commands', 'agents', 'skills', 'hooks', 'mcpServers', 'lspServers', 'monitors', 'outputStyles']) {
    const v = doc[key];
    const paths = typeof v === 'string' ? [v] : Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [];
    const bad = paths.filter(escapesRoot);
    if (bad.length) push(['hooks', 'mcpServers', 'lspServers', 'monitors'].includes(key) ? 'HIGH' : 'MEDIUM', `Plugin loads ${key} from outside the plugin (${bad[0]})`, 'Reference components by paths inside the plugin.', bad[0]);
  }
  const uc = isObj(doc.userConfig) ? Object.entries(doc.userConfig).map(([k, v]) => ({ key: k, sensitive: v?.sensitive })) : [];
  const gs = Array.isArray(doc.settings) ? doc.settings.filter(isObj).map((s) => ({ key: s.envVar ?? s.name, sensitive: s.sensitive })) : [];
  const plain = [...uc, ...gs].filter((c) => SECRETISH_KEY_RE.test(String(c.key ?? '')) && c.sensitive !== true);
  if (plain.length) push('MEDIUM', `Plugin collects a credential without marking it sensitive (${plain[0].key})`, 'Set `sensitive: true` on every field that carries a secret.', String(plain[0].key));
  for (const [label, map] of [['MCP server', doc.mcpServers], ['language server', doc.lspServers]]) {
    if (!isObj(map)) continue;
    for (const [n, s] of Object.entries(map)) {
      const args = Array.isArray(s?.args) ? s.args.map(String) : [];
      const line = [s?.command, ...args].join(' ');
      if (/\$\{user_config\.[\w.-]+\}/.test(line) && SHELL_COMMAND_RE.test(String(s?.command ?? '')) && args.some((x) => SHELL_FLAG_RE.test(x))) {
        push('HIGH', `Plugin substitutes user configuration into a shell command line (${label} "${n}")`, 'Pass configuration as its own argv entry or an environment variable, never inside `sh -c`.', n);
      }
    }
  }
  if (isObj(doc.lspServers)) out.push(...lspRows(doc.lspServers, 'Plugin', content));
  if (str(doc.migratedTo)) {
    const u = assessUrl(doc.migratedTo);
    push(u?.suspiciousHost || u?.metadataEndpoint ? 'HIGH' : u?.plaintext ? 'MEDIUM' : 'LOW', `Extension moves its own install source to ${doc.migratedTo}`, 'Confirm the new source is the same publisher and pin it.', 'migratedTo');
  }
  return out;
}

function lspRows(map, owner, content) {
  const out = [];
  for (const [n, s] of Object.entries(map).slice(0, 60)) {
    const spec = runnerUnpinned(s?.command, s?.args);
    if (spec) out.push({ severity: 'MEDIUM', title: `${owner} fetches language server "${n}" at an unpinned version (${spec})`, remediationText: 'Pin the package to an exact version or launch an installed binary.', line: lineOf(content, n) });
  }
  return out;
}

function mutating(op, method) {
  if (method && MUTATING_METHODS.has(method)) return true;
  const dh = op?.capabilities?.security_info?.data_handling;
  if (Array.isArray(dh) && dh.some((d) => /^(ResourceStateUpdate|DataExport)$/i.test(String(d)))) return true;
  return !method && MUTATING_VERB_RE.test(`${op?.name ?? ''} ${op?.description ?? ''}`.replace(/_/g, ' '));
}

export function localToolManifest(content, { path } = {}) {
  const out = [];
  const push = (severity, title, remediationText, needle) => out.push({ severity, title, remediationText, ...(needle ? { line: lineOf(content, needle) } : {}) });
  const doc = parse(content, path);
  if (!isObj(doc)) return out;

  if (isObj(doc.paths)) {
    const bypass = [];
    for (const [p, item] of Object.entries(doc.paths)) {
      if (!isObj(item)) continue;
      for (const m of MUTATING_METHODS) {
        const op = item[m];
        const flag = op?.['x-openai-isConsequential'] ?? op?.['x-oai-isConsequential'];
        if (isObj(op) && (flag === false || /^false$/i.test(String(flag ?? '').trim()))) bypass.push(op.operationId ?? `${m.toUpperCase()} ${p}`);
      }
    }
    if (bypass.length) push(bypass.some((n) => /delete|remove|transfer|pay|refund|purge|drop/i.test(n)) ? 'HIGH' : 'MEDIUM', `Action lets the model change state without asking (${bypass.slice(0, 3).join(', ')})`, 'Remove `x-openai-isConsequential: false` from state-changing operations.', 'isConsequential');
  }

  if (Array.isArray(doc.functions)) {
    const noConfirm = doc.functions.filter((f) => isObj(f) && mutating(f) && (/^none$/i.test(String(f.capabilities?.confirmation?.type ?? '')) || f.capabilities?.confirmation?.isNonConsequential === true));
    if (noConfirm.length) push('MEDIUM', `Plugin lets the model change state without asking (${noConfirm.slice(0, 3).map((f) => f.name).join(', ')})`, 'Use an AdaptiveCard confirmation on every function that changes state or exports data.', String(noConfirm[0].name));
    const mut = doc.functions.filter((f) => isObj(f) && mutating(f));
    for (const r of Array.isArray(doc.runtimes) ? doc.runtimes : []) {
      if (/^none$/i.test(String(r?.auth?.type ?? '')) && mut.length) push('MEDIUM', `Plugin runs state-changing functions against an unauthenticated ${r.type ?? 'runtime'}`, 'Put the runtime behind OAuthPluginVault or ApiKeyPluginVault.', 'auth');
      const u = assessUrl(r?.spec?.url);
      if (u?.suspiciousHost || u?.metadataEndpoint) push(u.metadataEndpoint ? 'CRITICAL' : 'HIGH', `Plugin routes model calls to ${u.suspiciousHost ?? 'the cloud metadata endpoint'}`, 'Remove this runtime.', u.url);
      else if (u?.plaintext && !u.privateNetwork) push('MEDIUM', 'Plugin loads a runtime over plaintext HTTP', 'Serve the runtime over https.', u.url);
    }
  }

  if (typeof doc.schema_version === 'string' && typeof doc.name_for_model === 'string') {
    const api = str(doc.api?.url);
    if (String(doc.auth?.type ?? '') === 'none' && api) push('MEDIUM', 'Tool manifest advertises an unauthenticated API', 'Require an authenticated scheme.', api);
    for (const key of ['client_url', 'authorization_url']) {
      const u = assessUrl(doc.auth?.[key]);
      if (u?.suspiciousHost) push('HIGH', `Tool manifest sends users to sign in at ${u.suspiciousHost}`, 'Use the provider\'s real authorization server.', u.url);
      else if (u?.plaintext && !u.privateNetwork) push('HIGH', 'Tool manifest runs its OAuth flow over plaintext HTTP', 'Use https for every OAuth endpoint.', u.url);
    }
    const u = assessUrl(api);
    if (u?.suspiciousHost || u?.metadataEndpoint) push(u.metadataEndpoint ? 'CRITICAL' : 'HIGH', `Tool manifest routes model traffic to ${u.suspiciousHost ?? 'the cloud metadata endpoint'}`, 'Remove this manifest.', api);
    else if (u?.plaintext && !u.privateNetwork) push('MEDIUM', 'Tool manifest points at a plaintext endpoint', 'Serve the API over https.', api);
  }

  if (typeof doc.instructions === 'string' && Array.isArray(doc.capabilities) && typeof doc.model !== 'string') {
    const caps = doc.capabilities.filter(isObj);
    const unscoped = (n, keys) => caps.some((c) => c.name === n && !keys.some((k) => (Array.isArray(c[k]) ? c[k].length : c[k])));
    const untrusted = unscoped('WebSearch', ['sites']) || unscoped('Email', ['shared_mailbox', 'group_mailboxes', 'folders']) || unscoped('TeamsMessages', ['urls']);
    const priv = caps.some((c) => ['OneDriveAndSharePoint', 'Email', 'TeamsMessages', 'Meetings', 'People', 'Dataverse', 'GraphConnectors'].includes(c.name));
    const sendsMail = caps.some((c) => c.name === 'EmailActions');
    const egress = sendsMail || caps.some((c) => c.name === 'MeetingActions') || (Array.isArray(doc.actions) && doc.actions.length > 0);
    const inboundOrWeb = caps.some((c) => c.name === 'Email') || unscoped('WebSearch', ['sites']);
    if (untrusted && priv && egress) push(sendsMail && inboundOrWeb ? 'HIGH' : 'MEDIUM', 'Declarative agent assembles the lethal trifecta from its capabilities', 'Scope WebSearch/mail/Teams to named items and split outward actions into a separate agent.', 'capabilities');
  }
  return out;
}

const SENSITIVE_DEFAULT_RE = /(^|[\/])(\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.config[\/]gcloud|\.azure|\.netrc|\.npmrc|\.git-credentials|Library[\/]Keychains)([\/]|$)/i;
const BROAD_DEFAULT_RE = /^(\/|~|~\/|[a-z]:[\/]?|\$\{?HOME\}?|%USERPROFILE%)$/i;

export function isDesktopExtensionDoc(doc) {
  if (!isObj(doc)) return false;
  if (typeof doc.dxt_version === 'string' || typeof doc.mcpb_version === 'string') return true;
  return isObj(doc.server) && (isObj(doc.server.mcp_config) || (typeof doc.manifest_version === 'string' && typeof doc.server.entry_point === 'string'));
}

export function localExtension(content, { path } = {}) {
  const out = [];
  const push = (severity, title, remediationText, needle) => out.push({ severity, title, remediationText, ...(needle ? { line: lineOf(content, needle) } : {}) });
  const doc = parse(content, path || 'manifest.json');
  if (!isDesktopExtensionDoc(doc)) return out;
  const name = String(doc.display_name ?? doc.name ?? 'extension');
  const cfg = isObj(doc.server?.mcp_config) ? doc.server.mcp_config : null;
  const launches = cfg ? [['default', cfg], ...Object.entries(isObj(cfg.platform_overrides) ? cfg.platform_overrides : {}).map(([k, o]) => [k, { ...cfg, ...o }])] : [];

  for (const [label, l] of launches) {
    const servers = { [label === 'default' ? name : `${name} (${label})`]: { command: l.command, args: l.args, env: l.env } };
    for (const f of gradeMcpDocument(JSON.stringify({ mcpServers: servers }), 'manifest.json').findings) push(f.severity, f.title, f.remediationText, f.server);
  }

  const fields = isObj(doc.user_config) ? Object.entries(doc.user_config).map(([key, v]) => ({ key, ...(isObj(v) ? v : {}) })) : [];
  const argText = launches.flatMap(([, l]) => (Array.isArray(l.args) ? l.args.map(String) : [])).join(' ');
  for (const [, l] of launches) {
    const line = [l.command, ...(Array.isArray(l.args) ? l.args : [])].join(' ');
    if (/\$\{user_config\.[\w.-]+\}/.test(line) && SHELL_COMMAND_RE.test(String(l.command ?? '')) && (l.args ?? []).some((x) => SHELL_FLAG_RE.test(String(x)))) {
      push('HIGH', `Extension "${name}" substitutes user configuration into a shell command line`, 'Pass configuration as its own argv entry or an environment variable, never inside `sh -c`.', 'user_config');
      break;
    }
  }
  const onArgv = fields.filter((f) => (f.sensitive === true || SECRETISH_KEY_RE.test(f.key)) && argText.includes(`\${user_config.${f.key}}`));
  if (onArgv.length) push('MEDIUM', `Extension "${name}" passes a credential on the command line (${onArgv[0].key})`, 'Pass secrets through mcp_config.env, not argv.', onArgv[0].key);
  const unmarked = fields.filter((f) => SECRETISH_KEY_RE.test(f.key) && f.sensitive !== true);
  if (unmarked.length) push('MEDIUM', `Extension "${name}" collects a credential without marking it sensitive (${unmarked[0].key})`, 'Set `sensitive: true` on every field that carries a secret.', unmarked[0].key);
  for (const f of fields) {
    if ((f.type !== 'directory' && f.type !== 'file') || typeof f.default !== 'string') continue;
    if (SENSITIVE_DEFAULT_RE.test(f.default)) push('HIGH', `Extension "${name}" defaults "${f.key}" to a credential store (${f.default})`, 'Leave the default empty or narrow it to a purpose-specific directory.', f.key);
    else if (BROAD_DEFAULT_RE.test(f.default.trim())) push('MEDIUM', `Extension "${name}" defaults "${f.key}" to the whole disk / home directory`, 'Leave the default empty or narrow it to a purpose-specific directory.', f.key);
  }
  if (doc.tools_generated === true || doc.prompts_generated === true) push('LOW', `Extension "${name}" generates its tools/prompts at runtime - the declared list is not the served one`, 'Scan the live server and pin the extension version.', 'generated');
  const entry = typeof doc.server?.entry_point === 'string' ? doc.server.entry_point.replace(/^\$\{__dirname\}\/?/, '') : null;
  if (entry && escapesRoot(entry)) push('HIGH', `Extension "${name}" runs an entry point outside its own bundle (${entry})`, 'Point entry_point at a file inside the bundle.', 'entry_point');
  return out;
}
