import { clampInt } from '../core/numbers.mjs';

export function parseEnvKV(str) {
  const env = {};
  for (const pair of String(str || '').split(',')) {
    const i = pair.indexOf('=');
    if (i > 0) env[pair.slice(0, i).trim()] = pair.slice(i + 1).trim();
  }
  return env;
}

const MCP_RUNNERS = new Set(['npx', '-y', '--yes', 'uvx', 'uv', 'node', 'bun', 'deno', 'python', 'python3', '-m', 'pipx', 'run', 'npm', 'pnpm', 'yarn', 'dlx', 'bunx']);

export function mcpLookupId(server, name) {
  if (server.url) return String(server.url);
  const toks = [server.command, ...(server.args || [])].filter(Boolean).map(String);
  for (const t of toks) {
    if (MCP_RUNNERS.has(t) || t.startsWith('-')) continue;
    if (/^@?[\w][\w./-]*$/.test(t)) return t;
  }
  return name;
}

export async function mcpLookup(url, id) {
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

export function mcpIndexAlert(index) {
  if (!index || !index.found || !index.scanned) return null;
  if (index.verdict === 'FAIL' || (index.criticalCount ?? 0) > 0) return 'BLOCK';
  if (index.verdict === 'REVIEW' || (index.highCount ?? 0) > 0) return 'FLAG';
  return 'OK';
}

export function worstMcpVerdict(local, idxAlert) {
  const rank = { ALLOW: 0, OK: 0, PASS: 0, FLAG: 1, REVIEW: 1, BLOCK: 2, FAIL: 2 };
  const label = ['ALLOW', 'FLAG', 'BLOCK'];
  return label[Math.max(rank[local] ?? 0, rank[idxAlert] ?? 0)];
}
