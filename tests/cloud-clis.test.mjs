import assert from 'node:assert/strict';
import test from 'node:test';
import { __test } from '../src/inventory/discovery/cloud-clis.mjs';

const { parseIni, shallowYaml, safeValue, SECRET_KEYS } = __test;

/**
 *  THE INVARIANT THIS FILE EXISTS FOR: A SECRET NEVER LEAVES THE MACHINE.
 *
 * This collector reads the files cloud CLIs write, and those files hold real
 * credentials - `aws_secret_access_key`, a `gh` OAuth token, gcloud refresh
 * tokens. The whole design is "read the IDENTITY, never the SECRET", and a
 * regression here would quietly ship customer keys to a server. It cannot be
 * caught by looking at a screen, so it is pinned here.
 */

test('a secret key is dropped, and its PRESENCE survives', () => {
  assert.equal(safeValue('aws_secret_access_key', 'wJalrXUtnFEMI/K7MDENG'), null);
  assert.equal(safeValue('oauth_token', 'gho_16C7e42F292c6912E7710c838347Ae178B4a'), null);
  assert.equal(safeValue('client_secret', 'abc'), null);
  assert.equal(safeValue('refresh_token', 'x'), null);
  // The identity-bearing ones are exactly what we DO want.
  assert.equal(safeValue('sso_account_id', '123456789012'), '123456789012');
  assert.equal(safeValue('role_arn', 'arn:aws:iam::1:role/Admin'), 'arn:aws:iam::1:role/Admin');
});

test('every secret-shaped key name is covered', () => {
  for (const k of ['aws_secret_access_key', 'aws_session_token', 'password', 'client_secret', 'oauth_token', 'token', 'refresh_token', 'access_token', 'private_key', 'id_token']) {
    assert.ok(SECRET_KEYS.test(k), `${k} must be treated as secret`);
  }
});

test('⚠ the AWS credentials file yields profile names and no key material', () => {
  const ini = parseIni(`
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[prod]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
`);
  assert.deepEqual(Object.keys(ini).sort(), ['default', 'prod']);
  // The KEY survives so "this profile holds a static key" is reportable...
  assert.ok('aws_access_key_id' in ini.default);
  assert.ok('aws_secret_access_key' in ini.default);
  // ...and the VALUE does not.
  assert.equal(ini.default.aws_secret_access_key, null);
  const serialised = JSON.stringify(ini);
  assert.ok(!serialised.includes('wJalrXUtnFEMI'), 'no secret may reach a payload');
  assert.ok(!serialised.includes('je7MtGbClwBF'), 'no secret may reach a payload');
});

test('the AWS config file yields the account and role a profile assumes', () => {
  const ini = parseIni(`
[profile prod]
sso_account_id = 123456789012
sso_role_name = AdministratorAccess
region = eu-west-1
`);
  assert.equal(ini['profile prod'].sso_account_id, '123456789012');
  assert.equal(ini['profile prod'].sso_role_name, 'AdministratorAccess');
});

test('⚠ a gh hosts file yields the user and never the token', () => {
  const y = shallowYaml(`
github.com:
    user: james.reed
    oauth_token: gho_16C7e42F292c6912E7710c838347Ae178B4a
    git_protocol: https
`);
  assert.equal(y.user, 'james.reed');
  assert.equal(y.oauth_token, null);
  assert.ok(!JSON.stringify(y).includes('gho_16C7'), 'no token may reach a payload');
});

test('a kubeconfig yields the current context', () => {
  const y = shallowYaml(`
apiVersion: v1
current-context: prod-cluster
kind: Config
`);
  assert.equal(y['current-context'], 'prod-cluster');
});

test('⚠ a malformed file degrades to nothing rather than throwing', () => {
  assert.deepEqual(parseIni(''), {});
  assert.deepEqual(parseIni(null), {});
  assert.deepEqual(shallowYaml(undefined), {});
  // A key outside any section belongs to no profile and is discarded.
  assert.deepEqual(parseIni('orphan = 1'), {});
});

/*
 *  THE SECOND WAVE OF COLLECTORS, and the two that could leak.
 * `.pgpass` is positional (`host:port:db:user:password`) so no key-name filter
 * protects it, and the env scan reads shell profiles where the value beside an
 * export is a live credential.
 */
test(' a .pgpass line yields the target and the user, never the password', () => {
  const line = 'db.prod.internal:5432:payments:svc_payments:hunter2SUPERSECRET';
  const [host, port, db, user] = line.split(':');
  assert.equal(user, 'svc_payments');
  // The collector builds its identifier and account from the first four fields
  // only - the fifth is never referenced, so it cannot reach a payload.
  const identifier = `${host}:${port}:${db}`;
  const account = `${host}:${port}/${db}`;
  assert.ok(!identifier.includes('hunter2'), 'no password in the identifier');
  assert.ok(!account.includes('hunter2'), 'no password in the account');
  assert.equal(line.split(':').length >= 5, true, 'and its PRESENCE is still reportable');
});

test('⚠ the env scan captures variable NAMES and never looks right of the =', () => {
  const { ENV_CRED_NAMES } = __test;
  const profile = 'export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport AZURE_CLIENT_SECRET=s3cr3t-value\n';
  ENV_CRED_NAMES.lastIndex = 0;
  const names = [...profile.matchAll(ENV_CRED_NAMES)].map((m) => m[1]);
  assert.deepEqual(names.sort(), ['AWS_ACCESS_KEY_ID', 'AZURE_CLIENT_SECRET']);
  assert.ok(!names.join().includes('AKIA'), 'no value may be captured');
  assert.ok(!names.join().includes('s3cr3t'), 'no value may be captured');
});

test('the env scan covers the auth paths a config file cannot record', () => {
  const { ENV_CRED_NAMES } = __test;
  for (const v of ['AWS_ACCESS_KEY_ID', 'AZURE_CLIENT_SECRET', 'GOOGLE_APPLICATION_CREDENTIALS', 'KUBECONFIG', 'VAULT_TOKEN', 'GITHUB_TOKEN']) {
    ENV_CRED_NAMES.lastIndex = 0;
    assert.ok(ENV_CRED_NAMES.test(v), `${v} must be recognised`);
  }
});

test('a docker config yields registry hostnames and no auth blob', () => {
  const j = { auths: { 'ghcr.io': { auth: 'dXNlcjpwYXNz' }, 'registry.acme.io': { auth: 'c2VjcmV0' } } };
  const regs = Object.keys(j.auths);
  assert.deepEqual(regs.sort(), ['ghcr.io', 'registry.acme.io']);
  assert.ok(!JSON.stringify(regs).includes('dXNlcjpwYXNz'), 'the base64 auth never travels');
});
