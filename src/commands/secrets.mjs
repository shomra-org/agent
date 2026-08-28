import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { MAX_ARTIFACT_BYTES, SKIP_DIRS } from '../artifacts/matchers.mjs';
import { clampInt } from '../core/numbers.mjs';
import { bold, cyan, dim, green, red, yellow } from '../core/terminal.mjs';
import { SECRET_PATTERNS, localScan } from '../detect/guard-signals.mjs';

function redactSecret(s) {
  const t = String(s).trim();
  return t.length <= 8 ? t[0] + '••••' : `${t.slice(0, 4)}…${t.slice(-2)}`;
}

function isGitRepo(root) {
  try { execSync('git rev-parse --is-inside-work-tree', { cwd: root, stdio: ['ignore', 'pipe', 'ignore'] }); return true; }
  catch { return false; }
}

export function walkFiles(root, cap = 8000) {
  const found = [];
  const stack = [root];
  while (stack.length && found.length < cap) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const ent of entries) {
      if (ent.isDirectory()) { if (!SKIP_DIRS.has(ent.name) && ent.name !== '.git') stack.push(path.join(dir, ent.name)); continue; }
      found.push(path.relative(root, path.join(dir, ent.name)).split(path.sep).join('/'));
      if (found.length >= cap) break;
    }
  }
  return found;
}

function scanGitHistory(root, depth) {
  let out;
  try { out = execSync(`git log --all -p -n ${depth} --no-color --format="commit %H %an %ad"`, { cwd: root, stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 128 * 1024 * 1024 }).toString(); }
  catch { return null; }
  const hits = [];
  const seen = new Set();
  let commit = '', file = '';
  for (const line of out.split(/\r?\n/)) {
    if (line.startsWith('commit ')) { commit = line.slice(7, 19); continue; }
    if (line.startsWith('+++ b/')) { file = line.slice(6); continue; }
    if (line[0] !== '+' || line.startsWith('+++')) continue;
    const added = line.slice(1);
    for (const { name, re } of SECRET_PATTERNS) {
      const m = added.match(re);
      if (!m) continue;
      const key = `${commit}:${file}:${name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push({ where: 'history', commit, file, secret: name, sample: redactSecret(m[0]) });
    }
  }
  return hits;
}

export function cmdSecrets(flags, positional) {
  const root = path.resolve(positional[0] || '.');
  const hits = [];
  const isGit = isGitRepo(root);
  for (const rel of walkFiles(root)) {
    let content;
    try {
      const full = path.join(root, rel);
      if (fs.statSync(full).size > MAX_ARTIFACT_BYTES) continue;
      content = fs.readFileSync(full, 'utf8');
    } catch { continue; }
    if (content.includes('\0')) continue;
    for (const f of localScan(content, { categories: ['secret'] }).findings) {
      hits.push({ where: 'working-tree', file: rel, line: f.line, secret: f.label.replace(/^Live credential:\s*/, '') });
    }
  }
  let history = null;
  if (flags.history) {
    history = scanGitHistory(root, clampInt(flags.depth, 300, 1, 5000));
    if (history) hits.push(...history);
  }

  if (flags.json) { console.log(JSON.stringify({ workingTree: hits.filter((h) => h.where === 'working-tree').length, history: history ? history.length : null, hits }, null, 2)); return; }

  console.log(bold(cyan('\n  Shomra secrets')) + dim(` - ${path.relative(process.cwd(), root).split(path.sep).join('/') || '.'}${flags.history ? ' · working tree + git history' : ' · working tree'}`));
  if (!isGit) console.log(dim('  (not a git repo - working tree only; --history unavailable)'));
  else if (!flags.history) console.log(dim('  Tip: add ') + bold('--history') + dim(' to also scan past commits (a leaked key removed from HEAD is still live).'));
  const wt = hits.filter((h) => h.where === 'working-tree');
  const hi = hits.filter((h) => h.where === 'history');
  if (!hits.length) { console.log(green('\n  ✓ No secret-shaped values found.\n')); return; }
  if (wt.length) {
    console.log(red(`\n  ${wt.length} in the working tree:`));
    for (const h of wt.slice(0, 25)) console.log(`    ${red('●')} ${bold(h.file)}${h.line ? dim(':' + h.line) : ''} ${dim(h.secret)}`);
  }
  if (hi.length) {
    console.log(yellow(`\n  ${hi.length} in git history ${dim('(rotate - still reachable):')}`));
    for (const h of hi.slice(0, 25)) console.log(`    ${yellow('●')} ${dim(h.commit)} ${bold(h.file)} ${dim(h.secret + ' ' + (h.sample || ''))}`);
  }
  console.log(dim(`\n  Rotate every matched credential now. A committed secret is compromised even after you delete it - history keeps it.\n`));
  process.exitCode = 1;
}
