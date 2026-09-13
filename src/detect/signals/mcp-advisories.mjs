import { gradeMcpDocument, knownVulnerable, launchPull } from './mcp-config.mjs';

const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN = 'https://api.osv.dev/v1/vulns/';
const MAX_PACKAGES = 40;
const MAX_DETAILS = 12;
const cache = new Map();

async function postJson(url, body, fetchImpl, timeoutMs) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  t.unref?.();
  try {
    const res = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: ctl.signal });
    if (!res.ok) throw new Error(`OSV ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

async function getJson(url, fetchImpl, timeoutMs) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  t.unref?.();
  try {
    const res = await fetchImpl(url, { signal: ctl.signal });
    if (!res.ok) throw new Error(`OSV ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

function severityOf(vuln) {
  const s = String(vuln?.database_specific?.severity ?? '').toUpperCase();
  if (s === 'CRITICAL' || s === 'HIGH') return s;
  if (s === 'MODERATE' || s === 'MEDIUM' || s === 'LOW') return 'MEDIUM';
  return 'HIGH';
}

function fixedOf(vuln, name) {
  const out = new Set();
  for (const aff of Array.isArray(vuln?.affected) ? vuln.affected : []) {
    if (aff?.package?.name && aff.package.name.toLowerCase() !== name.toLowerCase()) continue;
    for (const r of Array.isArray(aff?.ranges) ? aff.ranges : []) for (const e of Array.isArray(r?.events) ? r.events : []) if (e?.fixed) out.add(String(e.fixed));
  }
  return [...out];
}

export async function mcpAdvisoryFindings(content, path = '', { fetchImpl = globalThis.fetch, timeoutMs = 3500 } = {}) {
  const { servers } = gradeMcpDocument(content, path);
  const wanted = new Map();
  for (const s of servers ?? []) {
    if (s.disabled) continue;
    const p = launchPull(s.command, s.args);
    if (!p?.version) continue;
    if (knownVulnerable(p.ecosystem === 'pypi' ? 'python' : 'npm', p.name, p.version)) continue; // the seed row already says it
    const key = `${p.ecosystem}:${p.name.toLowerCase()}@${p.version}`;
    const slot = wanted.get(key) ?? { ...p, servers: [] };
    slot.servers.push(s.name);
    wanted.set(key, slot);
  }
  const pkgs = [...wanted.entries()].slice(0, MAX_PACKAGES);
  if (!pkgs.length) return { status: 'none', checked: 0, findings: [] };
  if (typeof fetchImpl !== 'function') return { status: 'unavailable', checked: 0, findings: [] };

  const todo = pkgs.filter(([k]) => !cache.has(k));
  if (todo.length) {
    let batch;
    try {
      batch = await postJson(OSV_BATCH, { queries: todo.map(([, p]) => ({ package: { ecosystem: p.ecosystem === 'pypi' ? 'PyPI' : 'npm', name: p.name }, version: p.version })) }, fetchImpl, timeoutMs);
    } catch {
      return { status: 'unavailable', checked: 0, findings: [] };
    }
    todo.forEach(([k], i) => cache.set(k, (batch?.results?.[i]?.vulns ?? []).map((v) => v.id).filter(Boolean)));
  }

  const ids = [...new Set(pkgs.flatMap(([k]) => cache.get(k) ?? []))].slice(0, MAX_DETAILS);
  const details = new Map();
  await Promise.all(ids.map(async (id) => {
    try { details.set(id, await getJson(OSV_VULN + encodeURIComponent(id), fetchImpl, timeoutMs)); } catch { /* the id alone still stands */ }
  }));

  const findings = [];
  const RANK = { MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
  for (const [k, p] of pkgs) {
    const vids = cache.get(k) ?? [];
    if (!vids.length) continue;
    const vulns = vids.map((id) => details.get(id)).filter(Boolean);
    const severity = vulns.length ? vulns.map(severityOf).reduce((w, s) => (RANK[s] > RANK[w] ? s : w), 'MEDIUM') : 'HIGH';
    const fixed = [...new Set(vulns.flatMap((v) => fixedOf(v, p.name)))].slice(0, 3);
    const cves = [...new Set(vulns.flatMap((v) => [v.id, ...(v.aliases ?? [])]).filter((x) => /^CVE-/i.test(x)))].slice(0, 3);
    for (const server of p.servers) {
      findings.push({
        severity,
        title: `MCP server "${server}" runs ${p.name}@${p.version}, which has known advisories`,
        remediationText: `Upgrade "${p.name}"${fixed.length ? ` to ${fixed.join(' / ')} or later` : ' past the affected range'} and pin that release. Advisories: ${[...cves, ...vids.filter((v) => !cves.includes(v))].slice(0, 5).join(', ')}.`,
        anchor: `${p.name}`,
        server,
      });
    }
  }
  return { status: 'checked', checked: pkgs.length, findings };
}

export function advisoriesDisabled(flags = {}) {
  return !!flags.offline || /^(1|true|yes)$/i.test(String(process.env.SHOMRA_OFFLINE ?? ''));
}
