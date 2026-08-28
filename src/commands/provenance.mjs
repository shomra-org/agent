import { execSync } from 'node:child_process';
import path from 'node:path';
import { api } from '../core/api-client.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { bold, cyan, dim, green, red, yellow } from '../core/terminal.mjs';

function gitChangedPaths(root, { staged, base }) {
  const run = (args) => {
    try {
      return execSync(`git ${args}`, { cwd: root, stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 }).toString();
    } catch {
      return null;
    }
  };
  let out = null;
  if (staged) {
    out = run('diff --cached --name-only --relative --diff-filter=ACM');
  } else if (base) {
    for (const b of [`origin/${base}`, base]) {
      out = run(`diff --name-only --relative --diff-filter=ACM ${b}...HEAD`);
      if (out !== null) break;
    }
  }
  if (out === null) out = run('diff HEAD~1 --name-only --relative --diff-filter=ACM');
  if (out === null) return null;
  return out.split('\n').map((s) => s.trim()).filter(Boolean);
}

export async function cmdProvenance(flags, positional) {
  const root = path.resolve(flags.path || positional[0] || '.');
  const staged = !!flags.staged;
  const base = flags.base || (staged ? null : process.env.GITHUB_BASE_REF || 'main');

  const paths = gitChangedPaths(root, { staged, base });
  if (paths === null) {
    console.error(red('✗') + ' Not a git repository (or no diff available). Run inside a repo, or pass --base <ref>.');
    process.exit(EXIT_USAGE);
  }
  if (!paths.length) {
    if (flags.json) console.log(JSON.stringify({ files: [], agentAuthored: 0, coverage: 'NO_TELEMETRY', summary: 'no changed files' }, null, 2));
    else console.log(green('\n  ✓ No changed files to attribute.\n'));
    return;
  }

  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  let res;
  try {
    res = await api(url, apiKey, '/gate/provenance', {
      paths,
      repo: flags.repo || process.env.GITHUB_REPOSITORY || undefined,
      sessionId: flags.session || undefined,
      sinceHours: flags.since ? Number(flags.since) : undefined,
    });
  } catch (e) {

    console.error(yellow('!') + ` Provenance unavailable (${e.message}). Authorship not established.`);
    process.exit(flags['fail-on-blocked'] ? 1 : EXIT_USAGE);
  }

  if (flags.json) {
    console.log(JSON.stringify(res, null, 2));
  } else if (flags.trailer) {
    for (const t of res.trailers || []) console.log(t);
  } else {
    const noTel = res.coverage === 'NO_TELEMETRY';
    console.log('');
    console.log(`  ${bold('Commit provenance')} ${dim(`· ${res.files.length} changed file(s)`)}`);
    console.log(`  ${noTel ? yellow('⚠ ' + res.summary) : res.summary}`);
    if (noTel) {
      console.log(dim('    No firewall telemetry for this range - this is NOT a claim that a human wrote them.'));
      console.log(dim('    Install the runtime hook with ') + bold('shomra protect') + dim(' to attribute future work.'));
    }
    console.log('');
    for (const f of res.files.slice(0, 40)) {
      const tag =
        f.authorship === 'AGENT' ? cyan('agent') : f.authorship === 'BLOCKED_ATTEMPT' ? red('blocked') : dim('unattributed');
      const who = f.agents?.length ? dim(` ${f.agents.join(', ')}`) : '';
      const amb = f.ambiguous ? yellow(' ~ambiguous') : '';
      console.log(`    ${tag.padEnd(22)} ${f.path}${who}${amb}`);
    }
    if (res.files.length > 40) console.log(dim(`    …and ${res.files.length - 40} more`));
    console.log('');
  }

  if (flags['fail-on-blocked'] && res.blockedAttempts > 0) {
    console.error(red('✗') + ` ${res.blockedAttempts} file(s) the firewall blocked were modified anyway.`);
    process.exit(1);
  }
}
