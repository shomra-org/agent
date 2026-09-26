import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { EXCHANGE_PATH, readCachedCredential, workloadCredential, workloadSource, writeCachedCredential } from '../src/core/workload-identity.mjs';

const URL_ = 'https://api.example';
const AUD = 'shomra:org:o1';
const tmp = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-wl-')), 'workload-credential.json');
const soon = (min) => new Date(Date.now() + min * 60_000).toISOString();
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

function stubFetch(responder) {
  const calls = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    return responder(String(url), init);
  };
  return { calls, restore: () => (globalThis.fetch = original) };
}

test('only a named platform turns keyless sign-in on', () => {
  assert.equal(workloadSource({ SHOMRA_WORKLOAD: 'GitHub' }), 'github');
  assert.equal(workloadSource({ SHOMRA_WORKLOAD: 'jenkins' }), null);
  assert.equal(workloadSource({}), null);
});

test('a cached credential is used until five minutes before it expires, and only for the same backend and audience', () => {
  const file = tmp();
  writeCachedCredential(file, { url: URL_, source: 'github', audience: AUD, credential: 'shm_agt_a', expiresAt: soon(30) });
  assert.equal(readCachedCredential(file, { url: URL_, source: 'github', audience: AUD }), 'shm_agt_a');
  assert.equal(readCachedCredential(file, { url: 'https://other.example', source: 'github', audience: AUD }), null);
  assert.equal(readCachedCredential(file, { url: URL_, source: 'github', audience: 'shomra:org:o2' }), null);
  writeCachedCredential(file, { url: URL_, source: 'github', audience: AUD, credential: 'shm_agt_a', expiresAt: soon(3) });
  assert.equal(readCachedCredential(file, { url: URL_, source: 'github', audience: AUD }), null);
  writeCachedCredential(file, { url: URL_, source: 'github', audience: AUD, credential: 'shm_live_org', expiresAt: soon(30) });
  assert.equal(readCachedCredential(file, { url: URL_, source: 'github', audience: AUD }), null);
});

test('the cache file is readable by its owner only', { skip: process.platform === 'win32' }, () => {
  const file = tmp();
  writeCachedCredential(file, { url: URL_, source: 'github', audience: AUD, credential: 'shm_agt_a', expiresAt: soon(30) });
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
});

test('a GitHub job asks for its token with the audience, exchanges it once, then reads the cache', async () => {
  const file = tmp();
  const env = { SHOMRA_WORKLOAD: 'github', SHOMRA_AUDIENCE: AUD, ACTIONS_ID_TOKEN_REQUEST_URL: 'https://gh.example/token?v=2', ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'runner' };
  const { calls, restore } = stubFetch((url) => (url.startsWith('https://gh.example') ? json(200, { value: 'gh-oidc' }) : json(200, { credential: 'shm_agt_minted', expiresAt: soon(60) })));
  try {
    assert.equal(await workloadCredential({ url: URL_, env, file }), 'shm_agt_minted');
    assert.equal(calls[0].url, `https://gh.example/token?v=2&audience=${encodeURIComponent(AUD)}`);
    assert.equal(calls[0].init.headers.Authorization, 'bearer runner');
    assert.equal(calls[1].url, `${URL_}${EXCHANGE_PATH}`);
    assert.deepEqual(JSON.parse(calls[1].init.body), { token: 'gh-oidc' });
    assert.equal(calls[1].init.headers['X-Shomra-Key'], undefined);
    assert.equal(await workloadCredential({ url: URL_, env, file }), 'shm_agt_minted');
    assert.equal(calls.length, 2);
  } finally {
    restore();
  }
});

test('a cluster reads its projected token from the file it names', async () => {
  const file = tmp();
  const tokenFile = path.join(path.dirname(file), 'token');
  fs.writeFileSync(tokenFile, 'k8s-oidc\n');
  const { calls, restore } = stubFetch(() => json(200, { credential: 'shm_agt_k8s', expiresAt: soon(60) }));
  try {
    const env = { SHOMRA_WORKLOAD: 'kubernetes', SHOMRA_AUDIENCE: AUD, SHOMRA_TOKEN_FILE: tokenFile };
    assert.equal(await workloadCredential({ url: URL_, env, file }), 'shm_agt_k8s');
    assert.deepEqual(JSON.parse(calls[0].init.body), { token: 'k8s-oidc' });
  } finally {
    restore();
  }
});

test('a refused sign-in reports why and yields no credential, so the hook falls back to its not-configured path', async () => {
  const file = tmp();
  const errors = [];
  const { restore } = stubFetch(() => json(401, { message: 'This token is not accepted for any agent.' }));
  try {
    const env = { SHOMRA_WORKLOAD: 'gitlab', SHOMRA_AUDIENCE: AUD, SHOMRA_ID_TOKEN: 'gl-oidc' };
    assert.equal(await workloadCredential({ url: URL_, env, file, onError: (e) => errors.push(e.message) }), null);
    assert.match(errors[0], /not accepted/);
    assert.equal(fs.existsSync(file), false);
  } finally {
    restore();
  }
});

test('without a platform, an audience or a backend nothing is fetched', async () => {
  const { calls, restore } = stubFetch(() => json(200, {}));
  try {
    assert.equal(await workloadCredential({ url: URL_, env: { SHOMRA_WORKLOAD: 'github' }, file: tmp() }), null);
    assert.equal(await workloadCredential({ url: null, env: { SHOMRA_WORKLOAD: 'github', SHOMRA_AUDIENCE: AUD }, file: tmp() }), null);
    assert.equal(calls.length, 0);
  } finally {
    restore();
  }
});

test('Entra and Okta are named platforms too', () => {
  assert.equal(workloadSource({ SHOMRA_WORKLOAD: 'Entra' }), 'entra');
  assert.equal(workloadSource({ SHOMRA_WORKLOAD: 'okta' }), 'okta');
});

const ENTRA_AUD = 'api://shomra';
const TID = '0f3c2b1a-1111-4222-8333-444455556666';

test('on AKS, the pod’s federated token buys an Entra token for the binding’s audience, with no stored secret', async () => {
  const file = tmp();
  const saToken = path.join(path.dirname(file), 'azure-identity-token');
  fs.writeFileSync(saToken, 'k8s-sa-token\n');
  const env = { SHOMRA_WORKLOAD: 'entra', SHOMRA_AUDIENCE: ENTRA_AUD, AZURE_TENANT_ID: TID, AZURE_CLIENT_ID: 'app-1', AZURE_FEDERATED_TOKEN_FILE: saToken, AZURE_AUTHORITY_HOST: 'https://login.microsoftonline.com/' };
  const { calls, restore } = stubFetch((url) => (url.includes('login.microsoftonline.com') ? json(200, { access_token: 'entra-at' }) : json(200, { credential: 'shm_agt_entra', expiresAt: soon(60) })));
  try {
    assert.equal(await workloadCredential({ url: URL_, env, file }), 'shm_agt_entra');
    assert.equal(calls[0].url, `https://login.microsoftonline.com/${TID}/oauth2/v2.0/token`);
    const form = new URLSearchParams(calls[0].init.body);
    assert.equal(form.get('scope'), 'api://shomra/.default');
    assert.equal(form.get('client_assertion'), 'k8s-sa-token');
    assert.equal(form.get('client_id'), 'app-1');
    assert.deepEqual(JSON.parse(calls[1].init.body), { token: 'entra-at' });
  } finally {
    restore();
  }
});

test('the federated token is never sent to an authority that is not https', async () => {
  const file = tmp();
  const saToken = path.join(path.dirname(file), 'azure-identity-token');
  fs.writeFileSync(saToken, 'k8s-sa-token');
  const errors = [];
  const { calls, restore } = stubFetch(() => json(200, { access_token: 'x' }));
  try {
    const env = { SHOMRA_WORKLOAD: 'entra', SHOMRA_AUDIENCE: ENTRA_AUD, AZURE_TENANT_ID: TID, AZURE_CLIENT_ID: 'app-1', AZURE_FEDERATED_TOKEN_FILE: saToken, AZURE_AUTHORITY_HOST: 'http://login.example/' };
    assert.equal(await workloadCredential({ url: URL_, env, file, onError: (e) => errors.push(e.message) }), null);
    assert.equal(calls.length, 0);
    assert.match(errors[0], /must be an https URL/);
  } finally {
    restore();
  }
});

test('on an Azure VM, the instance metadata service is asked for the audience', async () => {
  const file = tmp();
  const { calls, restore } = stubFetch((url) => (url.startsWith('http://169.254.169.254') ? json(200, { access_token: 'mi-at' }) : json(200, { credential: 'shm_agt_vm', expiresAt: soon(60) })));
  try {
    assert.equal(await workloadCredential({ url: URL_, env: { SHOMRA_WORKLOAD: 'entra', SHOMRA_AUDIENCE: ENTRA_AUD }, file }), 'shm_agt_vm');
    const asked = new URL(calls[0].url);
    assert.equal(asked.origin + asked.pathname, 'http://169.254.169.254/metadata/identity/oauth2/token');
    assert.equal(asked.searchParams.get('resource'), ENTRA_AUD);
    assert.equal(asked.searchParams.get('api-version'), '2018-02-01');
    assert.equal(calls[0].init.headers.Metadata, 'true');
  } finally {
    restore();
  }
});

test('on App Service or Container Apps, the local identity endpoint is asked with its header', async () => {
  const file = tmp();
  const env = { SHOMRA_WORKLOAD: 'entra', SHOMRA_AUDIENCE: ENTRA_AUD, IDENTITY_ENDPOINT: 'http://localhost:4141/msi/token', IDENTITY_HEADER: 'local-secret', AZURE_CLIENT_ID: 'uami-1' };
  const { calls, restore } = stubFetch((url) => (url.startsWith('http://localhost:4141') ? json(200, { access_token: 'app-at' }) : json(200, { credential: 'shm_agt_app', expiresAt: soon(60) })));
  try {
    assert.equal(await workloadCredential({ url: URL_, env, file }), 'shm_agt_app');
    const asked = new URL(calls[0].url);
    assert.equal(asked.searchParams.get('client_id'), 'uami-1');
    assert.equal(asked.searchParams.get('api-version'), '2019-08-01');
    assert.equal(calls[0].init.headers['X-IDENTITY-HEADER'], 'local-secret');
  } finally {
    restore();
  }
});

test('a token the environment already holds is exchanged as it is', async () => {
  const file = tmp();
  const { calls, restore } = stubFetch(() => json(200, { credential: 'shm_agt_given', expiresAt: soon(60) }));
  try {
    assert.equal(await workloadCredential({ url: URL_, env: { SHOMRA_WORKLOAD: 'entra', SHOMRA_AUDIENCE: ENTRA_AUD, SHOMRA_ID_TOKEN: 'held-at' }, file }), 'shm_agt_given');
    assert.equal(calls.length, 1);
    assert.deepEqual(JSON.parse(calls[0].init.body), { token: 'held-at' });
  } finally {
    restore();
  }
});

test('an Okta agent reads its token from the file it keeps, and says so when there is none', async () => {
  const file = tmp();
  const oktaFile = path.join(path.dirname(file), 'okta-token');
  fs.writeFileSync(oktaFile, 'okta-at\n');
  const { calls, restore } = stubFetch(() => json(200, { credential: 'shm_agt_okta', expiresAt: soon(60) }));
  try {
    assert.equal(await workloadCredential({ url: URL_, env: { SHOMRA_WORKLOAD: 'okta', SHOMRA_AUDIENCE: ENTRA_AUD, SHOMRA_TOKEN_FILE: oktaFile }, file }), 'shm_agt_okta');
    assert.deepEqual(JSON.parse(calls[0].init.body), { token: 'okta-at' });
    const errors = [];
    assert.equal(await workloadCredential({ url: URL_, env: { SHOMRA_WORKLOAD: 'okta', SHOMRA_AUDIENCE: 'api://other' }, file: tmp(), onError: (e) => errors.push(e.message) }), null);
    assert.match(errors[0], /no Okta token/);
    assert.equal(calls.length, 1);
  } finally {
    restore();
  }
});
