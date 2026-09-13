import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { SECRET_PATTERNS } from '../src/detect/signals/secrets.mjs';
import { redactLocally } from '../src/detect/local-redact.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT = path.join(here, '..', '..', 'Dragox.Backend', 'scripts', 'mirror-secret-patterns.mjs');

test('the generated secret mirror is in sync with the platform source', { skip: !fs.existsSync(SCRIPT) && 'platform checkout not present' }, async () => {
  const { stripTypeScriptTypes } = await import('node:module');
  if (typeof stripTypeScriptTypes !== 'function') return;
  const { render } = await import(pathToFileURL(SCRIPT).href);
  const local = fs.readFileSync(path.join(here, '..', 'src', 'detect', 'signals', 'secret-scanner.mjs'), 'utf8');
  assert.equal(local, render(), 'secret-scanner.mjs drifted - regenerate with Dragox.Backend/scripts/mirror-secret-patterns.mjs');
});

test('the list the agent masks with carries the providers the old hand-kept copy missed', () => {
  const names = new Set(SECRET_PATTERNS.map((p) => p.name));
  for (const n of ['PyPI upload token', 'Stripe live secret key', 'Mailgun key', 'Encrypted private key block', 'Credential in URL', 'Databricks token']) {
    assert.ok(names.has(n), `missing: ${n}`);
  }
});

test('local redaction masks what the old list let through', () => {
  const body = 'Qm8vT2xLp9RkW4sZ7nYb3HcJd6FgE1aU0oIiPq5rXtVwNyMzKlBj';
  for (const token of [`pypi-AgEIcHlwaS5vcmc${body}`, `rk_live_${body.slice(0, 30)}`, `key-${'3f'.repeat(16)}`, `dapi${'0a1b2c3d'.repeat(4)}`]) {
    const out = redactLocally(`deploy with ${token} now`);
    assert.ok(out.changed && !out.text.includes(token.slice(0, 12)), `left unmasked: ${token.slice(0, 16)}…`);
  }
});

test('a PEM header shown in docs is not masked as a key, a real body is', () => {
  assert.equal(redactLocally('PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"').changed, false);
  assert.equal(redactLocally('-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Vq3mKpQwErTyUiOpAsDfGh\n-----END RSA PRIVATE KEY-----').changed, true);
});
