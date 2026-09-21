import { api } from '../core/api-client.mjs';
import { git } from '../core/git-exec.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { EXIT_USAGE, exitNotConfigured } from '../core/exit-codes.mjs';
import { bold, cyan, dim, green, red } from '../core/terminal.mjs';

export async function cmdAgentIdentity(flags, positional) {
  const sub = (positional[0] || 'register').toLowerCase();
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  if (!apiKey) {
    exitNotConfigured();
  }
  if (sub !== 'register') {
    console.error(`\n  ${red('✗')} Unknown subcommand "${sub}". Use: ${bold('shomra agent-identity register --name "…" --type coding-agent')}`);
    console.error(dim('  (List / govern / revoke identities in the dashboard → Agent Identities.)\n'));
    process.exit(EXIT_USAGE);
  }
  let res;
  try {
    res = await api(url, apiKey, '/agents/register', {
      name: flags.name ? String(flags.name) : undefined,
      slug: flags.slug ? String(flags.slug) : undefined,
      type: flags.type ? String(flags.type) : undefined,
      ownerEmail: ownerEmail(flags),
      projectId: flags.project ? String(flags.project) : undefined,
    });
  } catch (e) {
    console.error(`\n  ${red('✗')} ${e.message}\n`);
    process.exit(1);
  }
  if (flags.json) {
    console.log(JSON.stringify(res, null, 2));
    return;
  }
  console.log(`\n  ${green('✓')} Registered agent identity ${bold(res.name)} ${dim('(' + res.slug + ' · ' + res.type + ')')}`);
  if (res.credential) {
    console.log(`\n  ${bold('Credential')} ${dim('(shown once - store it securely):')}`);
    console.log(`    ${cyan(res.credential)}`);
  }
  if (res.owner) {
    console.log(`  ${dim('Owner:')} ${res.owner.email ?? res.owner.name}`);
  } else {
    console.log(`\n  ${red('!')} ${bold('No owner recorded.')} ${dim('Nobody is accountable for this identity.')}`);
    console.log(dim(`    Re-run with --owner <email> (an active Shomra seat), or assign one in the dashboard.`));
  }
  if (res.handleShadow) {
    console.log(`\n  ${red('!')} ${bold('Another identity already answers to this name.')}`);
    console.log(dim(`    ${res.handleShadow.statement}`));
    console.log(dim(`    ${res.handleShadow.remedy}`));
  }
  console.log(`\n  Present this identity so every call is authorized as it:`);
  console.log(dim(`    export SHOMRA_AGENT=${res.slug}        # or use the credential above`));
  console.log(dim(`  Then set its least-privilege capabilities in the dashboard → Agent Identities.\n`));
}

export function ownerEmail(flags) {
  if (flags && flags.owner) return String(flags.owner).trim() || undefined;
  if (flags && flags['no-owner']) return undefined;
  try {
    const configured = git(['config', '--get', 'user.email'], { timeout: 2000 })?.trim();
    return configured || undefined;
  } catch {
    return undefined;
  }
}

export function resolveAgentIdentityHandle(flags) {
  const v = (flags && flags['agent-id'] && String(flags['agent-id'])) || process.env.SHOMRA_AGENT || '';
  return v && String(v).trim() ? String(v).trim() : null;
}
