import { assessUrl } from './egress.mjs';
import { lineAt, lineOf } from './lines.mjs';
import { MALICIOUS_PACKAGE_SEED, POPULAR_PACKAGES, editDistance, packageFromCommand } from './packages.mjs';
import { SECRET_PATTERNS } from './secrets.mjs';

export const HIGH_IMPACT_TOOLS = ['bash', 'shell', 'exec', 'execute', 'run', 'terminal', 'command', 'write', 'edit', 'multiedit', 'writefile', 'write_file', 'create', 'delete', 'remove', 'rm', 'webfetch', 'web_fetch', 'fetch', 'browser', 'network', 'http', 'curl', 'computer', 'automation'];

export function isWildcardGrant(t) { const s = t.trim().toLowerCase().replace(/^["']|["']$/g, ''); return s === '*' || s === 'all' || s === 'any'; }

export function baseToolName(t) { return t.split(/[(:\s]/)[0].trim().toLowerCase(); }

export function toToolList(v) {
  if (v == null) return [];
  if (Array.isArray(v)) return v.map((x) => String(x).trim()).filter(Boolean);
  return String(v).replace(/^\[|\]$/g, '').split(/[,\n]+/).map((t) => t.replace(/^["']|["']$/g, '').trim()).filter(Boolean);
}

export function frontmatter(text) {
  const m = /^﻿?---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text || '');
  if (!m) return {};
  const data = {};
  let key = null;
  for (const raw of m[1].split(/\r?\n/)) {
    if (!raw.trim() || raw.trim().startsWith('#')) continue;
    const li = /^\s*-\s+(.*)$/.exec(raw);
    if (li && key) { (Array.isArray(data[key]) ? data[key] : (data[key] = [])).push(li[1].trim().replace(/^["']|["']$/g, '')); continue; }
    const kv = /^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/.exec(raw);
    if (!kv) continue;
    key = kv[1];
    const val = kv[2].trim();
    data[key] = val === '' ? (data[key] ?? null) : val.startsWith('[') ? toToolList(val) : val.replace(/^["']|["']$/g, '');
  }
  return data;
}

function mcpServersFrom(content) {
  let json;
  try { json = JSON.parse(content); } catch { return []; }
  const map = json?.mcpServers ?? json?.servers ?? json?.mcp?.servers ?? json?.context_servers ?? {};
  if (!map || typeof map !== 'object') return [];
  return Object.entries(map).map(([name, cfg]) => ({ name, ...(cfg && typeof cfg === 'object' ? cfg : {}) }));
}

export function localMcp(content) {
  const out = [];
  const push = (severity, title, remediationText, line) => out.push({ severity, title, remediationText, ...(line ? { line } : {}) });
  for (const s of mcpServersFrom(content)) {
    const cmdLine = [s.command, ...(s.args ?? [])].filter(Boolean).join(' ');
    if (s.url && String(s.url).startsWith('http://')) {
      push('MEDIUM', `MCP server "${s.name}" uses plaintext HTTP`, 'Use an https:// endpoint and require an authenticated bearer token.', lineOf(content, String(s.url)));
    }
    const envBlob = JSON.stringify(s.env ?? {});
    for (const { name, re } of SECRET_PATTERNS) {
      if (re.test(envBlob) || re.test(cmdLine)) {
        push('CRITICAL', `Static credential in MCP server "${s.name}"`, 'Rotate the credential and pass it via a runtime env reference, not a literal in the config.', lineOf(content, re));
        break;
      }
    }
    const pkg = packageFromCommand(s.command, s.args ?? []);
    if (pkg) {
      if (MALICIOUS_PACKAGE_SEED.has(pkg)) {
        push('CRITICAL', `MCP server "${s.name}" runs a known-malicious package (${pkg})`, 'Remove this server and audit for compromise. Replace with a vetted alternative.', lineOf(content, pkg));
      } else {
        const squat = POPULAR_PACKAGES.find((p) => p !== pkg && editDistance(pkg, p) === 1);
        if (squat) push('MEDIUM', `Possible typosquat in "${s.name}": ${pkg} (looks like "${squat}")`, `Confirm the intended package is "${squat}", not "${pkg}", and pin it.`, lineOf(content, pkg));
      }
    }
  }
  return out;
}

export function localAgentCard(content) {
  const out = [];
  const push = (severity, title, remediationText, line) => out.push({ severity, title, remediationText, ...(line ? { line } : {}) });
  let card;
  try { card = JSON.parse(content); } catch { return out; }
  const urls = new Set();
  if (card?.url) urls.add(String(card.url));
  for (const key of ['endpoints', 'endpoint', 'servers']) {
    const v = card?.[key];
    if (Array.isArray(v)) v.forEach((x) => typeof x === 'string' && urls.add(x));
    else if (typeof v === 'string') urls.add(v);
  }
  for (const sk of Array.isArray(card?.skills) ? card.skills : []) if (sk?.url) urls.add(String(sk.url));
  const seen = new Set();
  for (const raw of urls) {
    const u = assessUrl(raw);
    if (!u) continue;
    const line = lineOf(content, u.url);
    if (u.metadataEndpoint && !seen.has('metadata')) { seen.add('metadata'); push('CRITICAL', `Agent card targets the cloud metadata endpoint (${u.url})`, 'Remove this card immediately - a known SSRF credential-theft pattern.', line); }
    else if (u.privateNetwork && !seen.has('private')) { seen.add('private'); push('MEDIUM', `Agent card declares a private-network endpoint (${u.url})`, 'Publish only public, TLS-protected endpoints in shared agent cards.', line); }
    if (u.suspiciousHost && !seen.has('exfil')) { seen.add('exfil'); push('HIGH', `Agent card points at an exfiltration-style endpoint (${u.suspiciousHost})`, 'Do not interoperate with this agent; replace the endpoint with the vendor\'s real domain.', line); }
    if (u.plaintext && !u.privateNetwork && !seen.has('plaintext')) { seen.add('plaintext'); push('MEDIUM', `Agent card uses plaintext HTTP (${u.url})`, 'Serve the agent over https:// only.', line); }
    if (u.rawIp && !u.privateNetwork && !seen.has('rawip')) { seen.add('rawip'); push('LOW', `Agent card addresses its endpoint by raw IP (${u.url})`, 'Use a DNS hostname with a valid TLS certificate.', line); }
  }
  const hasAuth = !!(card?.securitySchemes || card?.authentication || card?.security || card?.auth);
  if (card?.url && !hasAuth) push('MEDIUM', 'Agent card declares no authentication scheme', 'Declare and enforce an auth scheme (OAuth2 / API key / mTLS) and reject unauthenticated requests.');
  return out;
}

export function localCommandExtras(content) {
  const out = [];
  const body = content || '';
  const bang = [...body.matchAll(/^!\s*`?([^`\n]+)`?/gm)];
  if (bang.length) {
    const line = bang[0].index != null ? lineAt(body, bang[0].index) : undefined;
    out.push({ severity: 'LOW', title: `Command runs ${bang.length} shell command(s) before the prompt`, remediationText: 'Confirm each "!" command is fixed and safe; avoid interpolating untrusted arguments.', ...(line ? { line } : {}) });
  }
  const atRefs = [...body.matchAll(/(?:^|\s)@([~./][^\s`]+)/g)].map((m) => m[1]);
  const sensitive = atRefs.find((r) => /(\.env|\.ssh|id_rsa|secret|credential|\.pem|\.key)/i.test(r));
  if (sensitive) out.push({ severity: 'MEDIUM', title: `Command attaches a sensitive file (@${sensitive})`, remediationText: 'Do not auto-attach secret/key files to prompts; reference only non-sensitive, scoped files.', line: lineOf(body, `@${sensitive}`) });
  return out;
}
