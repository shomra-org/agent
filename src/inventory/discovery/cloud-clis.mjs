import path from 'node:path';
import { exists, readJson, readText } from './fs-read.mjs';
import { userDirs } from './platform.mjs';

/**
 * WHAT THIS MACHINE IS LOGGED INTO.
 *
 *  THE ASSET IS THE AMBIENT CREDENTIAL, NOT THE BINARY. "az is installed" is
 * worth nothing. "az on this host is authenticated as `sp-jamesr-automation`
 * against subscription `prod-01`" is the whole finding, because an agent with a
 * shell on this host inherits exactly that - a reach nothing in the agent's own
 * policy granted, that YOUR credential rotation does not touch, and that
 * SUSPENDING THE AGENT DOES NOT REVOKE.
 *
 *  NOTHING HERE EXECUTES A COMMAND. `az account show` would be the obvious
 * way and it is the wrong one: spawning cloud CLIs on a customer's machine is
 * slow, can trigger interactive re-auth, and can itself mint or refresh tokens -
 * a collector that changes the estate it measures. Every fact below is read out
 * of a config file the CLI already wrote.
 *
 *  AND IT NEVER READS SECRET MATERIAL. `~/.aws/credentials` holds
 * `aws_secret_access_key`; `gh` holds an OAuth token; gcloud's `credentials.db`
 * holds refresh tokens. This parses the IDENTITY-BEARING keys only and is
 * written so a secret cannot reach the payload even by accident - see
 * `SECRET_KEYS` and the profile-name-only parse of the credentials file.
 */

/**
 * Keys that carry secret material. A parser that meets one drops the VALUE and
 * keeps only the fact that it was present.
 *
 * ⚠ Presence is a finding ("this host holds a long-lived key"); the value is
 * never ours to move.
 */
const SECRET_KEYS =
  /^(aws_secret_access_key|aws_session_token|password|client_secret|oauth_token|token|refresh_token|access_token|private_key|id_token)$/i;

/** ⚠ The one place a value is allowed to leave this file. */
function safeValue(key, value) {
  if (SECRET_KEYS.test(String(key ?? '').trim())) return null;
  const v = String(value ?? '').trim();
  return v.length > 200 ? v.slice(0, 200) : v;
}

/** A minimal INI reader - `~/.aws/config` and `~/.aws/credentials`. */
function parseIni(text) {
  const out = {};
  let section = '';
  for (const raw of String(text ?? '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const head = /^\[(.+)\]$/.exec(line);
    if (head) {
      section = head[1].trim();
      out[section] = out[section] ?? {};
      continue;
    }
    const eq = line.indexOf('=');
    if (eq < 0 || !section) continue;
    const key = line.slice(0, eq).trim();
    const value = safeValue(key, line.slice(eq + 1));
    out[section] = out[section] ?? {};
    // ⚠ The KEY is kept even when the value is dropped, so "this profile has a
    // long-lived secret key" survives without the key itself.
    out[section][key] = value;
  }
  return out;
}

/** `key: value` out of a shallow YAML file, values sanitised. Never a parser. */
function shallowYaml(text) {
  const out = {};
  for (const raw of String(text ?? '').split(/\r?\n/)) {
    const m = /^\s{0,4}([A-Za-z0-9_.-]+):\s*(.*)$/.exec(raw);
    if (!m) continue;
    const v = m[2].replace(/^["']|["']$/g, '');
    out[m[1]] = safeValue(m[1], v);
  }
  return out;
}

/**
 * EVERY VENDOR THIS FILE CAN EMIT, DECLARED IN ONE PLACE.
 *
 *  THE VENDOR VOCABULARY IS A GATED SURFACE. `vendor-vocabulary-bench`
 * greps the agent for `vendor: '…'` and requires every slug to land in exactly
 * one bucket, so a new vendor fails loudly instead of arriving unclassified.
 * Most vendors here are passed POSITIONALLY to `asset()`, which that grep cannot
 * see - so it caught four of the twenty and stayed silent about the rest. This
 * list exists so the gate sees ALL of them.
 *
 * ⚠ THESE ARE NOT AI VENDORS. They answer "what is this host logged into",
 * not "which AI destination does this org use" - see `CLOUD_PLATFORM_VENDORS`
 * on the backend, the bucket that says so.
 */
export const CLOUD_CLI_VENDORS = [
  { vendor: '1password' }, { vendor: 'aws' }, { vendor: 'azure' }, { vendor: 'cargo' },
  { vendor: 'databricks' }, { vendor: 'digitalocean' }, { vendor: 'docker' }, { vendor: 'env' },
  { vendor: 'gcp' }, { vendor: 'github' }, { vendor: 'kubernetes' }, { vendor: 'mysql' },
  { vendor: 'netrc' }, { vendor: 'npm' }, { vendor: 'oracle' }, { vendor: 'postgres' },
  { vendor: 'pypi' }, { vendor: 'snowflake' }, { vendor: 'ssh' }, { vendor: 'terraform' },
  { vendor: 'vault' },
];

const asset = (name, vendor, identifier, metadata) => ({
  type: 'CLOUD_CLI',
  name,
  identifier,
  vendor,
  metadata: { category: 'cloud-cli', ...metadata },
});

/**
 * Azure. `azureProfile.json` names every subscription the CLI is logged into
 * AND the principal it authenticated as - `user` or `servicePrincipal`.
 */
function azure(HOME) {
  const file = path.join(HOME, '.azure', 'azureProfile.json');
  if (!exists(file)) return [];
  const profile = readJson(file);
  const subs = Array.isArray(profile?.subscriptions) ? profile.subscriptions : [];
  if (!subs.length) return [asset('Azure CLI', 'azure', file, { provider: 'azure', principal: null, note: 'installed, no subscription in its profile' })];

  return subs.slice(0, 20).map((s) =>
    asset('Azure CLI', 'azure', `${file}#${s.id ?? s.name ?? ''}`, {
      provider: 'azure',
      principal: s?.user?.name ?? null,
      // ⚠ `servicePrincipal` is the one that matters most: it is a NON-HUMAN
      // credential sitting on a developer's laptop, and nobody is prompted.
      principalType: s?.user?.type ?? null,
      account: s?.name ?? null,
      accountId: s?.id ?? null,
      isDefault: !!s?.isDefault,
      state: s?.state ?? null,
      tenantId: s?.tenantId ?? null,
    }),
  );
}

/** AWS. Profiles, the account/role they assume, and whether a static key sits here. */
function aws(HOME) {
  const cfgFile = path.join(HOME, '.aws', 'config');
  const credFile = path.join(HOME, '.aws', 'credentials');
  if (!exists(cfgFile) && !exists(credFile)) return [];

  const cfg = parseIni(readText(cfgFile) ?? '');
  const creds = parseIni(readText(credFile) ?? '');
  const names = new Set([
    ...Object.keys(cfg).map((k) => k.replace(/^profile\s+/, '')),
    ...Object.keys(creds),
  ]);

  return [...names].slice(0, 20).map((profileName) => {
    const c = cfg[`profile ${profileName}`] ?? cfg[profileName] ?? {};
    const k = creds[profileName] ?? {};
    return asset('AWS CLI', 'aws', `${credFile}#${profileName}`, {
      provider: 'aws',
      profile: profileName,
      principal: c.role_arn ?? c.sso_role_name ?? null,
      accountId: c.sso_account_id ?? null,
      account: c.sso_start_url ?? c.region ?? null,
      ssoSession: c.sso_session ?? null,
      /*
       * ⚠ A LONG-LIVED STATIC KEY, reported as a PRESENCE and never as a value.
       * It is the worst shape on this list: no expiry, no device binding, and
       * an agent with a shell reads it as easily as the CLI does.
       */
      hasStaticKey: Object.prototype.hasOwnProperty.call(k, 'aws_access_key_id'),
    });
  });
}

/** Google Cloud. The active account and project out of the config file. */
function gcp(HOME) {
  const file = path.join(HOME, '.config', 'gcloud', 'configurations', 'config_default');
  if (!exists(file)) return [];
  const ini = parseIni(readText(file) ?? '');
  const core = ini.core ?? {};
  /*
   *  `gcp`, NOT `google`. The shadow-AI vocabulary aliases `google` to
   * `google-ai`, so emitting it here would have turned "this host has gcloud
   * logged in" into "this org uses Google AI" - an AI-usage claim manufactured
   * from a cloud CLI that has never served a token.
   */
  return [
    asset('gcloud CLI', 'gcp', file, {
      provider: 'gcp',
      principal: core.account ?? null,
      account: core.project ?? null,
      accountId: core.project ?? null,
    }),
  ];
}

/**
 * Kubernetes. The CURRENT context is the one a bare `kubectl` acts on, which is
 * the only one an agent reaches without naming anything.
 */
function kubernetes(HOME) {
  const file = path.join(HOME, '.kube', 'config');
  if (!exists(file)) return [];
  const y = shallowYaml(readText(file) ?? '');
  const current = y['current-context'] ?? null;
  return [
    asset('kubectl', 'kubernetes', file, {
      provider: 'kubernetes',
      principal: y.user ?? null,
      account: current,
      accountId: current,
      // ⚠ A context this file names but does not point at is reach the agent has
      // only if it asks for it - a weaker claim, and reported as one.
      currentContext: current,
    }),
  ];
}

/** GitHub CLI. The user it is logged in as; never the token. */
function github(HOME) {
  const file = path.join(HOME, '.config', 'gh', 'hosts.yml');
  if (!exists(file)) return [];
  const y = shallowYaml(readText(file) ?? '');
  return [
    asset('GitHub CLI', 'github', file, {
      provider: 'github',
      principal: y.user ?? null,
      account: y.git_protocol ? 'github.com' : null,
      hasStaticKey: /oauth_token:/.test(readText(file) ?? ''),
    }),
  ];
}

/**
 * TERRAFORM. The state backend and the Terraform Cloud token.
 *
 * ⚠ The highest-consequence entry on this list for infrastructure: a `terraform
 * apply` is a control-plane call with the blast radius of a whole workspace, and
 * it authenticates with credentials that are usually NOT the ones `az` or `aws`
 * hold - so an estate that governs those two still has this one open.
 */
function terraform(HOME) {
  const rc = [path.join(HOME, '.terraformrc'), path.join(HOME, 'terraform.rc')].find(exists);
  const tfc = path.join(HOME, '.terraform.d', 'credentials.tfrc.json');
  const out = [];
  if (rc) out.push(asset('Terraform', 'terraform', rc, { provider: 'terraform', principal: null, hasStaticKey: /token\s*=/.test(readText(rc) ?? '') }));
  if (exists(tfc)) {
    const j = readJson(tfc);
    for (const host of Object.keys(j?.credentials ?? {}).slice(0, 10)) {
      out.push(asset('Terraform Cloud', 'terraform', tfc + '#' + host, { provider: 'terraform', account: host, principal: null, hasStaticKey: true }));
    }
  }
  return out;
}

/** Docker/OCI registries this host can push to. Registry NAMES, never the auth blob. */
function docker(HOME) {
  const file = path.join(HOME, '.docker', 'config.json');
  if (!exists(file)) return [];
  const j = readJson(file);
  const regs = Object.keys(j?.auths ?? {}).slice(0, 15);
  if (!regs.length) return [asset('Docker', 'docker', file, { provider: 'registry', principal: null })];
  // ⚠ A registry login is a PUBLISH path - the supply chain, outbound.
  return regs.map((r) => asset('Docker registry', 'docker', file + '#' + r, { provider: 'registry', account: r, principal: null, hasStaticKey: true }));
}

/**
 * Package registries this host can PUBLISH to.
 *
 * ⚠ An agent that can publish is an agent that can ship code to everyone who
 * installs it. It is inventory for the same reason the cloud entries are.
 */
function packageRegistries(HOME) {
  const out = [];
  const npmrc = path.join(HOME, '.npmrc');
  if (exists(npmrc)) {
    const t = readText(npmrc) ?? '';
    const reg = /registry\s*=\s*(\S+)/.exec(t);
    out.push(asset('npm', 'npm', npmrc, { provider: 'registry', account: reg ? reg[1] : 'registry.npmjs.org', principal: null, hasStaticKey: /_authToken\s*=/.test(t) }));
  }
  const pypirc = path.join(HOME, '.pypirc');
  if (exists(pypirc)) {
    const ini = parseIni(readText(pypirc) ?? '');
    for (const name of Object.keys(ini).filter((k) => k !== 'distutils').slice(0, 6)) {
      const sect = ini[name] ?? {};
      out.push(asset('PyPI', 'pypi', pypirc + '#' + name, { provider: 'registry', account: name, principal: sect.username ?? null, hasStaticKey: 'password' in sect }));
    }
  }
  const cargo = path.join(HOME, '.cargo', 'credentials.toml');
  if (exists(cargo)) out.push(asset('crates.io', 'cargo', cargo, { provider: 'registry', principal: null, hasStaticKey: true }));
  return out;
}

/**
 * Databases this host has stored credentials for.
 *
 *  `.pgpass` IS `host:port:db:user:password` AND THE LAST FIELD IS THE SECRET.
 * It is split positionally and only the first four fields are ever named - the
 * one place in this file where a naive read would put a production database
 * password into a payload.
 */
function databases(HOME) {
  const out = [];
  const pgpass = path.join(HOME, '.pgpass');
  if (exists(pgpass)) {
    for (const line of (readText(pgpass) ?? '').split(/\r?\n/).slice(0, 40)) {
      const t = line.trim();
      if (!t || t.startsWith('#')) continue;
      const parts = t.split(':');
      const [host, port, db, user] = parts;
      out.push(
        asset('PostgreSQL', 'postgres', pgpass + '#' + host + ':' + port + ':' + db, {
          provider: 'database',
          account: (host ?? '') + ':' + (port ?? '') + '/' + (db ?? ''),
          principal: user ?? null,
          hasStaticKey: parts.length >= 5,
        }),
      );
    }
  }
  const mycnf = path.join(HOME, '.my.cnf');
  if (exists(mycnf)) {
    const c = parseIni(readText(mycnf) ?? '').client ?? {};
    out.push(asset('MySQL', 'mysql', mycnf, { provider: 'database', account: c.host ?? null, principal: c.user ?? null, hasStaticKey: 'password' in c }));
  }
  return out;
}

/**
 * SSH - the oldest lateral-movement path on the machine, and one an agent with a
 * shell uses with no CLI at all.
 *
 * ⚠ Host aliases and key PRESENCE only. A private key is never read, and a key
 * with no passphrase cannot be told from one with a passphrase without reading
 * it - so this reports that a key exists and nothing more.
 */
function ssh(HOME) {
  const dir = path.join(HOME, '.ssh');
  if (!exists(dir)) return [];
  const hosts = [];
  for (const line of (readText(path.join(dir, 'config')) ?? '').split(/\r?\n/)) {
    const m = /^\s*Host\s+(.+)$/i.exec(line);
    if (m) hosts.push(...m[1].trim().split(/\s+/).filter((h) => h && h !== '*'));
  }
  const keys = ['id_rsa', 'id_ed25519', 'id_ecdsa'].filter((k) => exists(path.join(dir, k)));
  if (!hosts.length && !keys.length) return [];
  return [
    asset('SSH', 'ssh', dir, {
      provider: 'ssh',
      principal: null,
      account: hosts.slice(0, 15).join(', ') || null,
      hostCount: hosts.length,
      hasStaticKey: keys.length > 0,
    }),
  ];
}

/**
 * THE CREDENTIAL BROKERS.
 *
 *  Worse than any single credential on this list, because a broker token is a
 * key to every other key - and it is the one entry whose blast radius does not
 * shrink when you tidy up the others.
 */
function brokers(HOME) {
  const out = [];
  const vault = path.join(HOME, '.vault-token');
  if (exists(vault)) out.push(asset('HashiCorp Vault', 'vault', vault, { provider: 'broker', principal: null, hasStaticKey: true }));
  const op = path.join(HOME, '.config', 'op', 'config');
  if (exists(op)) {
    const j = readJson(op);
    const acct = Array.isArray(j?.accounts) ? j.accounts[0] : null;
    out.push(asset('1Password CLI', '1password', op, { provider: 'broker', principal: acct?.email ?? null, account: acct?.url ?? null }));
  }
  return out;
}

/** The rest, all the same shape: a config file naming an account. */
function otherClouds(HOME) {
  const out = [];
  const simple = [
    { name: 'Databricks', vendor: 'databricks', file: path.join(HOME, '.databrickscfg'), provider: 'databricks' },
    { name: 'Snowflake CLI', vendor: 'snowflake', file: path.join(HOME, '.snowflake', 'config'), provider: 'snowflake' },
    { name: 'OCI CLI', vendor: 'oracle', file: path.join(HOME, '.oci', 'config'), provider: 'oci' },
    { name: 'doctl', vendor: 'digitalocean', file: path.join(HOME, '.config', 'doctl', 'config.yaml'), provider: 'digitalocean' },
  ];
  for (const c of simple) {
    if (!exists(c.file)) continue;
    const ini = parseIni(readText(c.file) ?? '');
    const first = Object.keys(ini)[0];
    const sect = ini[first] ?? {};
    out.push(
      asset(c.name, c.vendor, c.file, {
        provider: c.provider,
        account: sect.host ?? sect.tenancy ?? first ?? null,
        principal: sect.user ?? sect.username ?? null,
        hasStaticKey: 'token' in sect || 'password' in sect || 'key_file' in sect,
      }),
    );
  }
  // `.netrc` backs heroku, fly and everything else that never wrote its own file.
  const netrc = [path.join(HOME, '.netrc'), path.join(HOME, '_netrc')].find(exists);
  if (netrc) {
    const machines = [...(readText(netrc) ?? '').matchAll(/machine\s+(\S+)/gi)].map((m) => m[1]).slice(0, 15);
    for (const m of machines) out.push(asset('netrc credential', 'netrc', netrc + '#' + m, { provider: 'netrc', account: m, principal: null, hasStaticKey: true }));
  }
  return out;
}

/**
 * ENV-VAR AUTH - the case a file scan STRUCTURALLY cannot see.
 *
 *  `AWS_ACCESS_KEY_ID` exported in a shell profile writes NO config file, so
 * every collector above returns nothing and that reads identically to "this host
 * reaches no cloud". This looks where the export actually lives. It STILL misses
 * a variable injected by CI, a container env, or an IMDS role - which is exactly
 * why the surface must say "no config was found", never "no cloud".
 *
 * ⚠ NAMES ONLY. The value beside an export is a live credential; the pattern
 * captures the variable NAME and never looks right of the `=`.
 */
const ENV_CRED_NAMES =
  /\b(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AWS_PROFILE|AZURE_CLIENT_ID|AZURE_CLIENT_SECRET|AZURE_TENANT_ID|GOOGLE_APPLICATION_CREDENTIALS|GCLOUD_PROJECT|KUBECONFIG|VAULT_TOKEN|DATABRICKS_TOKEN|SNOWFLAKE_ACCOUNT|DIGITALOCEAN_ACCESS_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|DOCKER_PASSWORD)\b/g;

function envAuth(HOME, own = true) {
  const names = new Set();
  for (const f of ['.bashrc', '.bash_profile', '.zshrc', '.profile', '.zprofile'].map((n) => path.join(HOME, n))) {
    if (!exists(f)) continue;
    for (const m of (readText(f) ?? '').matchAll(ENV_CRED_NAMES)) names.add(m[1]);
  }
  // The live process env is the other half - a variable set by whatever launched
  // this scan, which no profile file records.
  for (const k of own ? Object.keys(process.env) : []) {
    ENV_CRED_NAMES.lastIndex = 0;
    if (ENV_CRED_NAMES.test(k)) names.add(k);
  }
  if (!names.size) return [];
  return [
    asset('Environment credentials', 'env', 'env://cloud-credentials', {
      provider: 'env',
      principal: null,
      variables: [...names].sort().slice(0, 30),
      hasStaticKey: true,
    }),
  ];
}

/**
 * Every cloud CLI this host is authenticated to.
 *
 * ⚠ AN EMPTY RESULT IS "NO CONFIG FILE WAS FOUND", never "this host reaches no
 * cloud". A CLI authenticated purely through an environment variable, an IMDS
 * role or a mounted service-account token writes no config and appears nowhere
 * here - the collector reports what it read, and the surface says so.
 */
export function discoverCloudClis(opts = {}) {
  const { HOME, own } = userDirs(opts.home);
  return [
    ...azure(HOME),
    ...aws(HOME),
    ...gcp(HOME),
    ...kubernetes(HOME),
    ...github(HOME),
    ...terraform(HOME),
    ...docker(HOME),
    ...packageRegistries(HOME),
    ...databases(HOME),
    ...ssh(HOME),
    ...brokers(HOME),
    ...otherClouds(HOME),
    ...envAuth(HOME, own),
  ];
}

export const __test = { parseIni, shallowYaml, safeValue, SECRET_KEYS, ENV_CRED_NAMES };
