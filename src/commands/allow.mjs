import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { bold, dim, green, red, yellow } from '../core/terminal.mjs';
import { DANGEROUS_SHELL } from '../detect/guard-signals.mjs';
import { MULTI_STAGE_NAME } from '../detect/signals/fetch-exec.mjs';
import {
  ALLOWS_FILE,
  DESTRUCTIVE_RULE,
  NEVER_ALLOWABLE,
  loadOrgAllows,
  readUserAllows,
  repoAllowStatus,
  repoPathStatus,
  slugRule,
  trustRepoLines,
  writeUserAllows,
} from '../guard/allows.mjs';
import { IGNORE_EDIT } from '../guard/self-protect.mjs';

const MAX_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
const ONCE_TTL_MS = 24 * 60 * 60 * 1000;

export function ruleCatalog() {
  const out = new Map();
  for (const s of DANGEROUS_SHELL) out.set(s.id ?? slugRule(s.name), { name: s.name, severity: s.severity, confirm: !!s.confirm });
  out.set('multi-stage-fetch-exec', { name: MULTI_STAGE_NAME, severity: 'CRITICAL' });
  out.set('staged-fetch-exec', { name: 'Downloads a file and then executes it (staged fetch-to-execute)', severity: 'CRITICAL' });
  out.set(slugRule('Encoded shell / RCE payload (base64, hex, percent or char-code)'), { name: 'Encoded shell / RCE payload (base64, hex, percent or char-code)', severity: 'CRITICAL' });
  out.set(IGNORE_EDIT.id, { name: IGNORE_EDIT.label, severity: IGNORE_EDIT.severity, confirm: true });
  out.set(DESTRUCTIVE_RULE, { name: 'A destructive command (delete, hard reset, force push, volume wipe) that asks before it runs', severity: 'ASK' });
  return out;
}

export function parseWindow(text) {
  const m = /^(\d{1,4})\s*(m|min|h|hr|d)$/i.exec(String(text ?? '').trim());
  if (!m) return null;
  const n = Number(m[1]);
  const unit = m[2].toLowerCase();
  const ms = n * (unit.startsWith('m') ? 60_000 : unit.startsWith('h') ? 3_600_000 : 86_400_000);
  return ms > 0 && ms <= MAX_WINDOW_MS ? ms : null;
}

function fail(message) {
  console.error(`${red('✗')} ${message}`);
  process.exit(EXIT_USAGE);
}

function usage() {
  console.log(`
  ${bold('shomra allow')} ${dim('- let one firewall rule through, narrowly, when you know it is fine')}

  ${bold('shomra allow <rule> --once')}            ${dim('the next matching call only (default)')}
  ${bold('shomra allow <rule> --for 1h')}          ${dim('every matching call for a window (max 30d)')}
  ${bold('shomra allow <rule> --in-repo')}         ${dim('this repo, for everyone, via .shomraignore')}
      ${dim('--match <text>   only when the command contains <text> (required for critical rules unless --once)')}
      ${dim('--reason <text>  a note for whoever reads the allow later')}
  ${bold('shomra allow --list')}                   ${dim('what is allowed right now, and from where')}
  ${bold('shomra allow --trust-repo')}             ${dim("review this repo's .shomraignore allows; add --yes to trust them on this machine")}
  ${bold('shomra allow --revoke <id>')}            ${dim('remove one of your allows')}
  ${bold('shomra allow --rules')}                  ${dim('every rule id this version knows')}
`);
}

function list(cwd) {
  const now = Date.now();
  const user = readUserAllows().filter((a) => !a.usedAt && (!a.expiresAt || Date.parse(a.expiresAt) > now));
  const repo = repoAllowStatus(cwd);
  const org = loadOrgAllows();
  const line = (a) => `${bold(a.rule)}${a.match ? dim(` · when it contains "${a.match}"`) : dim(' · any command')}`;
  console.log('');
  console.log(`  ${bold('Yours')} ${dim(`(${ALLOWS_FILE})`)}`);
  if (!user.length) console.log(`    ${dim('none')}`);
  for (const a of user) console.log(`    ${line(a)} ${dim(`· ${a.once ? 'once' : `until ${a.expiresAt}`} · id ${a.id}`)}`);
  console.log(`  ${bold('This Repo')} ${dim('(.shomraignore)')}`);
  if (!repo.length) console.log(`    ${dim('none')}`);
  for (const a of repo) console.log(`    ${line(a)} ${a.trusted ? dim('· trusted on this machine') : yellow('· NOT trusted - ignored until you run shomra allow --trust-repo')}`);
  for (const p of repoPathStatus(cwd)) console.log(`    ${bold('path')} ${p.glob} ${p.trusted ? dim('· not screened · trusted on this machine') : yellow('· NOT trusted - still screened until you run shomra allow --trust-repo')}`);
  console.log(`  ${bold('Your Org')} ${dim('(synced from the platform when enrolled)')}`);
  if (!org.length) console.log(`    ${dim('none')}`);
  for (const a of org) console.log(`    ${line(a)}${a.expiresAt ? dim(` · until ${a.expiresAt}`) : ''}`);
  console.log('');
}

function rules() {
  console.log('');
  for (const [id, r] of ruleCatalog()) console.log(`  ${bold(id.padEnd(44))} ${dim(`${r.severity.padEnd(8)} ${r.name}`)}`);
  console.log('');
}

function trustRepo(cwd, confirmed) {
  const catalog = ruleCatalog();
  const pending = [...repoAllowStatus(cwd), ...repoPathStatus(cwd)].filter((a) => !a.trusted);
  if (!pending.length) {
    console.log(`\n  ${green('✓')} ${dim('Nothing to review - every allow in this repo is already trusted, or it has none.')}\n`);
    return;
  }
  const inert = (a) => !a.match && (catalog.get(a.rule)?.severity === 'CRITICAL' || a.rule === DESTRUCTIVE_RULE);
  console.log(`\n  ${bold("This repo's .shomraignore asks to allow:")}`);
  for (const a of pending) {
    if (a.glob != null) {
      console.log(`    ${bold('path')} ${a.glob} ${dim('· the firewall does not screen files matching this')}`);
      continue;
    }
    const known = catalog.get(a.rule);
    const what = known ? `${known.severity} · ${known.name}` : 'a rule this version does not know';
    const note = inert(a) ? yellow(' · has no --match, so it will never apply to a critical rule') : '';
    console.log(`    ${bold(a.rule)}${a.match ? dim(` · when the command contains "${a.match}"`) : dim(' · any command')} ${dim(`(${what})`)}${note}`);
  }
  if (!confirmed) {
    console.log(`\n  ${dim('A cloned repo can ask for anything here. Trust it only if you know who wrote these lines.')}`);
    console.log(`  ${dim('To trust them on this machine:')} ${bold('shomra allow --trust-repo --yes')}\n`);
    return;
  }
  trustRepoLines(cwd, pending.map((a) => (a.glob != null ? { glob: a.glob } : { rule: a.rule, match: a.match })));
  console.log(`\n  ${green('✓')} Trusted ${pending.length} allow${pending.length === 1 ? '' : 's'} for ${bold(cwd)} ${dim('- a changed line needs trusting again')}\n`);
}

function revoke(id) {
  const all = readUserAllows();
  const kept = all.filter((a) => a.id !== id);
  if (kept.length === all.length) fail(`No allow with id ${bold(id)} ${dim('- see shomra allow --list')}`);
  writeUserAllows(kept);
  console.log(`\n  ${green('✓')} Revoked ${bold(id)}\n`);
}

function appendRepoAllow(cwd, rule, match, reason) {
  const file = path.join(cwd, '.shomraignore');
  let prefix = '';
  try {
    const cur = fs.readFileSync(file, 'utf8');
    if (cur && !cur.endsWith('\n')) prefix = '\n';
  } catch {
  }
  const note = reason ? `# ${reason.replace(/[\r\n]+/g, ' ').slice(0, 200)}\n` : '';
  fs.appendFileSync(file, `${prefix}${note}rule:${rule}${match ? `::${match}` : ''}\n`);
  return file;
}

export function cmdAllow(flags, positional = [], { stdin = process.stdin, stdout = process.stdout, cwd = process.cwd(), now = Date.now() } = {}) {
  if (flags.help) return usage();
  if (flags.list) return list(cwd);
  if (flags.rules) return rules();
  if (typeof flags.revoke === 'string') return revoke(flags.revoke);
  if (flags['trust-repo'] === true) {
    if (!stdin?.isTTY || !stdout?.isTTY) fail(`${bold('shomra allow --trust-repo')} is for a person at a terminal. ${dim('It is refused without one, so an agent cannot trust a repo for you.')}`);
    return trustRepo(cwd, flags.yes === true);
  }

  const rule = String(positional[0] ?? '').trim().toLowerCase();
  if (!rule) return usage();
  if (!/^[a-z0-9-]{1,80}$/.test(rule)) fail(`${bold(rule)} is not a rule id ${dim('- see shomra allow --rules')}`);
  if (NEVER_ALLOWABLE.has(rule)) fail(`${bold(rule)} cannot be allowed ${dim("- it guards Shomra's own allowlist, which an agent must never be able to edit")}`);

  if (!stdin?.isTTY || !stdout?.isTTY) {
    fail(`${bold('shomra allow')} is for a person at a terminal. ${dim('It is refused without one, so an agent that was just blocked cannot allow itself.')}`);
  }

  const catalog = ruleCatalog();
  const known = catalog.get(rule);
  if (!known) console.log(`  ${yellow('!')} ${bold(rule)} ${dim('is not a rule this version knows - saving it anyway, it may come from a newer rule set')}`);

  const match = typeof flags.match === 'string' && flags.match.trim() ? flags.match.trim().slice(0, 200) : undefined;
  const reason = typeof flags.reason === 'string' ? flags.reason.trim().slice(0, 200) : undefined;
  const windowMs = flags.for !== undefined ? parseWindow(flags.for) : null;
  if (flags.for !== undefined && !windowMs) fail(`--for takes a window like ${bold('30m')}, ${bold('1h')} or ${bold('7d')} ${dim('(max 30d)')}`);
  const scopes = [flags.once === true, windowMs !== null, flags['in-repo'] === true].filter(Boolean).length;
  if (scopes > 1) fail('Pick one of --once, --for or --in-repo');
  const once = scopes === 0 || flags.once === true;

  if (!once && !match && (known?.severity === 'CRITICAL' || rule === DESTRUCTIVE_RULE)) {
    fail(`${bold(rule)} is a critical rule - a standing allow needs ${bold('--match <text>')} so it covers one thing, not everything`);
  }

  if (flags['in-repo'] === true) {
    const file = appendRepoAllow(cwd, rule, match, reason);
    trustRepoLines(cwd, [{ rule, match }]);
    console.log(`\n  ${green('✓')} Allowed ${bold(rule)}${match ? ` when the command contains ${bold(match)}` : ''} in this repo ${dim(`(${file})`)}`);
    console.log(`  ${dim('Commit .shomraignore so the team shares it - and so review sees it.')}\n`);
    return;
  }

  const entry = {
    id: crypto.randomBytes(4).toString('hex'),
    rule,
    ...(match ? { match } : {}),
    ...(once ? { once: true } : {}),
    ...(reason ? { reason } : {}),
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + (once ? ONCE_TTL_MS : windowMs)).toISOString(),
  };
  const list0 = readUserAllows().filter((a) => !a.usedAt && (!a.expiresAt || Date.parse(a.expiresAt) > now));
  writeUserAllows([...list0, entry]);
  const scope = once ? 'for the next matching call' : `until ${entry.expiresAt}`;
  console.log(`\n  ${green('✓')} Allowed ${bold(rule)}${match ? ` when the command contains ${bold(match)}` : ''} ${scope} ${dim(`· id ${entry.id}`)}`);
  console.log(`  ${dim('Revoke with')} ${bold(`shomra allow --revoke ${entry.id}`)}\n`);
}
