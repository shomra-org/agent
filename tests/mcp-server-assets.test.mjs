import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { discoverMcpServers } from '../src/inventory/discovery/mcp-servers.mjs';
import { redactEnv } from '../src/inventory/discovery/model-keys.mjs';

test('the env shown and stored with an MCP server asset carries keys, never a value short enough to read back', () => {
  assert.deepEqual(redactEnv({
    GITHUB_TOKEN: 'ghp_16C7e42F292c6912E7710c838347Ae178B4a',
    DB_PASSWORD: 'hunter2',
    PIN: '123456',
    SHORT_SECRET: 'Winter!2025x',
    REGION: 'us-east-1',
    DEBUG: 'true',
    EMPTY: '',
  }), {
    GITHUB_TOKEN: 'ghp…4a',
    DB_PASSWORD: '…',
    PIN: '…',
    SHORT_SECRET: '…',
    REGION: '…',
    DEBUG: 'true',
    EMPTY: '',
  });
  assert.deepEqual(redactEnv(null), {});
});

test('a discovered MCP server reports its env keys in metadata without the raw values', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-mcp-assets-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-mcp-home-'));
  fs.writeFileSync(path.join(root, '.mcp.json'), JSON.stringify({
    mcpServers: { pg: { command: 'uvx', args: ['pg-mcp==1.0'], env: { DB_PASSWORD: 'hunter2', DB_HOST: 'localhost' } } },
  }));
  const pg = discoverMcpServers([root], null, { home }).find((a) => a.name === 'pg');
  assert.ok(pg, 'the server was discovered');
  assert.deepEqual(Object.keys(pg.metadata.env), ['DB_PASSWORD', 'DB_HOST']);
  assert.equal(JSON.stringify(pg.metadata).includes('hunter2'), false);
  assert.equal(JSON.stringify(pg.metadata).includes('localhost'), false);
});
