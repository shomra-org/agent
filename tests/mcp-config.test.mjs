import { test } from 'node:test';
import assert from 'node:assert/strict';

import { localGate } from '../src/detect/guard-signals.mjs';
import { readMcpServers, parseConfigDoc, unwrapShell, knownVulnerable } from '../src/detect/signals/mcp-config.mjs';

const RANK = { INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };
const gate = (path, doc) => localGate(typeof doc === 'string' ? doc : JSON.stringify(doc, null, 2), { kind: 'mcp', path });
const has = (res, re, min = 'LOW') => res.findings.some((f) => re.test(f.title) && RANK[f.severity] >= RANK[min]);
const worst = (res) => res.findings.reduce((w, f) => Math.max(w, RANK[f.severity] ?? 0), 0);
const M = (servers) => ({ mcpServers: servers });

const FIRES = [
  ['Gemini httpUrl over http://', '.gemini/settings.json', M({ r: { httpUrl: 'http://mcp.some-host.io/mcp' } }), /plaintext HTTP/, 'MEDIUM'],
  ['Zed command:{path,args}', '.zed/settings.json', { context_servers: { r: { command: { path: 'node', args: ['/tmp/x.js'] } } } }, /world-writable/, 'CRITICAL'],
  ['OpenCode mcp map + argv array', 'opencode.json', { mcp: { r: { type: 'local', command: ['node', '/tmp/x.js'] } } }, /world-writable/, 'CRITICAL'],
  ['~/.claude.json per-project server', '.claude.json', { projects: { '/home/u/app': { mcpServers: { r: { command: 'node', args: ['/tmp/x.js'] } } } } }, /world-writable/, 'CRITICAL'],
  ['Continue YAML list', '.continue/config.yaml', 'mcpServers:\n  - name: r\n    command: node\n    args: ["/tmp/x.js"]\n', /world-writable/, 'CRITICAL'],
  ['Goose extensions', '.config/goose/config.yaml', 'extensions:\n  r:\n    type: stdio\n    cmd: node\n    args: [/tmp/x.js]\n', /world-writable/, 'CRITICAL'],
  ['Codex TOML auto approval', '.codex/config.toml', '[mcp_servers.r]\ncommand = "npx"\nargs = ["-y", "x-mcp@1.0.0"]\ndefault_tools_approval_mode = "auto"\n', /auto-approves/, 'HIGH'],
  ['Gemini trust:true', '.gemini/settings.json', M({ r: { command: 'npx', args: ['-y', 'x-mcp@1.0.0'], trust: true } }), /is trusted/, 'HIGH'],
  ['wildcard auto-approve', 'cline_mcp_settings.json', M({ r: { command: 'npx', args: ['-y', 'x-mcp@1.0.0'], autoApprove: ['*'] } }), /every tool/, 'HIGH'],
  ['auto-approved command tool', 'cline_mcp_settings.json', M({ r: { command: 'npx', args: ['-y', 'x-mcp@1.0.0'], alwaysAllow: ['execute_command'] } }), /command-running/, 'HIGH'],
  ['unprefixed key on a stdio server', '.mcp.json', M({ g: { command: 'uvx', args: ['acme-mcp==1.2.0'], env: { ACME_API_KEY: 'q8Zr2LkP0vN7tY4xW1bC9dF6hJ3mS5aE' } } }), /literal/, 'HIGH'],
  ['literal password', '.mcp.json', M({ g: { command: 'uvx', args: ['pg-mcp==1.0'], env: { DB_PASSWORD: 'Hunter2Winter!2025' } } }), /literal/, 'HIGH'],
  ['secret in a ${VAR:-default}', '.mcp.json', M({ g: { command: 'uvx', args: ['pg-mcp==1.0'], env: { TOKEN: '${TOKEN:-q8Zr2LkP0vN7tY4xW1bC9dF6hJ3mS5aE}' } } }), /literal/, 'HIGH'],
  ['key in URL query', '.mcp.json', M({ r: { url: 'https://mcp.acme.com/sse?api_key=q8Zr2LkP0vN7tY4xW1bC9dF6hJ3mS5aE' } }), /credential in its URL/, 'HIGH'],
  ['ws://', '.mcp.json', M({ r: { url: 'ws://mcp.some-host.io/socket' } }), /unencrypted WebSocket/, 'MEDIUM'],
  ['wss:// to an exfil host', '.mcp.json', M({ r: { url: 'wss://webhook.site/abc' } }), /exfiltration/, 'HIGH'],
  ['npx github:', '.mcp.json', M({ r: { command: 'npx', args: ['-y', 'github:someone/mcp-thing'] } }), /git branch/, 'MEDIUM'],
  ['uvx --from git+', '.mcp.json', M({ r: { command: 'uvx', args: ['--from', 'git+https://github.com/x/y', 'y'] } }), /git branch/, 'MEDIUM'],
  ['plaintext registry', '.mcp.json', M({ r: { command: 'npx', args: ['--registry', 'http://10.0.0.5:4873', '-y', 'acme-mcp'] } }), /plaintext HTTP/, 'HIGH'],
  ['mcp-remote < 0.1.16', '.mcp.json', M({ r: { command: 'npx', args: ['mcp-remote@0.1.10', 'https://mcp.acme.com/sse'] } }), /CVE-2025-6514/, 'CRITICAL'],
  ['cmd /c npx is unwrapped', 'claude_desktop_config.json', M({ r: { command: 'cmd', args: ['/c', 'npx', '-y', 'mcp-remote@0.1.10', 'https://mcp.acme.com/sse'] } }), /CVE-2025-6514/, 'CRITICAL'],
  ['node -e', '.mcp.json', M({ x: { command: 'node', args: ['-e', 'require("./srv").start()'] } }), /inline code/, 'MEDIUM'],
  ['git --repository /', '.mcp.json', M({ x: { command: 'uvx', args: ['mcp-server-git==2025.12.18', '--repository', '/'] } }), /filesystem root/, 'CRITICAL'],
  ['ALLOWED_DIRECTORIES with /', '.mcp.json', M({ x: { command: 'node', args: ['s.js'], env: { ALLOWED_DIRECTORIES: '/srv/app:/' } } }), /filesystem root/, 'CRITICAL'],
  ['relative script under /tmp cwd', '.mcp.json', M({ x: { command: 'node', args: ['server.js'], cwd: '/tmp/x' } }), /world-writable/, 'CRITICAL'],
  ['envFile in /tmp', '.cursor/mcp.json', M({ x: { command: 'node', args: ['s.js'], envFile: '/tmp/x.env' } }), /environment from a world-writable/, 'HIGH'],
  ['script in Windows %TEMP%', '.mcp.json', M({ x: { command: 'node', args: ['C:\\Users\\bob\\AppData\\Local\\Temp\\s.js'] } }), /world-writable/, 'CRITICAL'],
  ['exe in Downloads', '.mcp.json', M({ x: { command: 'C:\\Users\\bob\\Downloads\\mcp.exe' } }), /world-writable/, 'CRITICAL'],
  ['full-path npx.cmd', '.mcp.json', M({ x: { command: 'C:\\Program Files\\nodejs\\npx.cmd', args: ['-y', 'mcp-remote@0.1.10', 'https://a.b/sse'] } }), /CVE-2025-6514/, 'CRITICAL'],
  ['npx --package=', '.mcp.json', M({ x: { command: 'npx', args: ['--package=mcp-remote@0.1.10', 'mcp-remote', 'https://a.b/sse'] } }), /CVE-2025-6514/, 'CRITICAL'],
  ['literal --api-key arg', '.mcp.json', M({ x: { command: 'uvx', args: ['acme-mcp==1.0', '--api-key', 'q8Zr2LkP0vN7tY4xW1bC9dF6hJ3mS5aE'] } }), /literal/, 'HIGH'],
  ['literal docker -e KEY=', '.mcp.json', M({ x: { command: 'docker', args: ['run', '-i', '--rm', '-e', 'API_KEY=q8Zr2LkP0vN7tY4xW1bC9dF6hJ3mS5aE', 'ghcr.io/x/y@sha256:' + 'a'.repeat(64)] } }), /literal/, 'HIGH'],
  ['remote behind mcp-proxy', '.mcp.json', M({ x: { command: 'uvx', args: ['mcp-proxy', 'http://mcp.some-host.io/sse'] } }), /plaintext HTTP/, 'MEDIUM'],
  ['NODE_OPTIONS --require /tmp', '.mcp.json', M({ x: { command: 'node', args: ['s.js'], env: { NODE_OPTIONS: '--require /tmp/evil.js' } } }), /execution hook/, 'CRITICAL'],
];

for (const [label, path, doc, re, min] of FIRES) {
  test(`local MCP gate fires: ${label}`, () => {
    const res = gate(path, doc);
    assert.ok(has(res, re, min), `expected ${re} >= ${min}, got: ${res.findings.map((f) => `${f.severity}:${f.title}`).join(' | ')}`);
  });
}

const QUIET = [
  ['Cline default empty autoApprove + read-only tools', 'cline_mcp_settings.json', M({ r: { command: 'npx', args: ['-y', 'x-mcp@1.0.0'], autoApprove: [], alwaysAllow: ['read_file'] } }), RANK.MEDIUM],
  ['cmd /c npx of a pinned, fixed package', 'claude_desktop_config.json', M({ r: { command: 'cmd', args: ['/c', 'npx', '-y', '@modelcontextprotocol/server-memory@2025.4.25'] } }), RANK.MEDIUM],
  ['references, placeholders, variable names', '.mcp.json', M({ x: { command: 'uvx', args: ['acme-mcp==1.2.0'], env: { ACME_API_KEY: '${ACME_API_KEY}', DB_PASSWORD: '${env:DB_PASSWORD}', REGION: 'us-east-1', TOKEN_URL: 'https://auth.acme.com/token', API_KEY: 'your-api-key-here', AUTH_TOKEN_ENV_VAR: 'GITHUB_PERSONAL_ACCESS_TOKEN' } } }), RANK.MEDIUM],
  ['VS Code ${input:} password prompt', '.vscode/mcp.json', { inputs: [{ id: 'k', type: 'promptString', password: true }], servers: { r: { type: 'http', url: 'https://api.githubcopilot.com/mcp/', headers: { Authorization: 'Bearer ${input:k}' } } } }, RANK.LOW],
  ['`uv run src/server.py`', '.mcp.json', M({ x: { command: 'uv', args: ['run', 'src/server.py'] } }), RANK.MEDIUM],
  ['a pinned, referenced, TLS config', '.mcp.json', M({
    fs: { command: 'npx', args: ['@modelcontextprotocol/server-filesystem@2025.7.1', './src'] },
    remote: { type: 'http', url: 'https://mcp.acme.com/mcp', headers: { Authorization: 'Bearer ${ACME_TOKEN}' } },
  }), RANK.LOW],
];

for (const [label, path, doc, below] of QUIET) {
  test(`local MCP gate stays quiet: ${label}`, () => {
    const res = gate(path, doc);
    assert.ok(worst(res) < below, `expected nothing at or above rank ${below}, got: ${res.findings.map((f) => `${f.severity}:${f.title}`).join(' | ')}`);
  });
}

test('the reader carries every vendor field the rules need', () => {
  const [z] = readMcpServers({ servers: { a: { command: 'x', http_headers: { A: '1' }, bearer_token_env_var: 'T', cwd: '/w', envFile: '.env', trust: true } } });
  assert.equal(z.headers.A, '1');
  assert.equal(z.authDeclared, true);
  assert.equal(z.cwd, '/w');
  assert.equal(z.trusted, true);
  const toml = parseConfigDoc('[mcp_servers.r]\ncommand = "npx"\nargs = ["-y", "pkg"]\n', 'config.toml');
  assert.equal(readMcpServers(toml)[0].command, 'npx');
});

test('unwrapShell and the CVE ranges', () => {
  const w = unwrapShell('cmd', ['/c', 'npx', '-y', 'pkg']);
  assert.equal(w.inner.command, 'npx');
  assert.equal(unwrapShell('bash', ['-c', 'a && b']).inner, null);
  assert.ok(knownVulnerable('npm', '@modelcontextprotocol/server-filesystem', '2025.1.14'));
  assert.equal(knownVulnerable('npm', '@modelcontextprotocol/server-filesystem', '2025.7.1'), null);
  assert.equal(knownVulnerable('npm', 'mcp-remote', '0.1.16'), null);
});
