import fs from 'node:fs';
import path from 'node:path';

export const MAX_RUN_TARGETS = 5;
export const MAX_RUN_TEXT = 16 * 1024;
const MAX_FILE = 256 * 1024;
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh']);
const WRAPPERS = new Set(['sudo', 'doas', 'env', 'exec', 'nohup', 'time', 'command', 'nice']);
const NPM_SCRIPT_VERBS = new Set(['test', 't', 'tst', 'start', 'stop', 'restart']);
const PNPM_OWN = new Set(['add', 'install', 'i', 'update', 'up', 'upgrade', 'remove', 'rm', 'uninstall', 'link', 'ln', 'unlink', 'import', 'rebuild', 'rb', 'prune', 'fetch', 'patch', 'patch-commit', 'audit', 'list', 'ls', 'outdated', 'why', 'exec', 'dlx', 'create', 'publish', 'pack', 'store', 'init', 'env', 'setup', 'config', 'root', 'bin', 'licenses', 'deploy', 'doctor', 'server', 'help', 'self-update', 'dedupe', 'cat-file', 'cat-index', 'find-hash', 'ignored-builds', 'approve-builds']);
const YARN_OWN = new Set(['add', 'install', 'remove', 'upgrade', 'up', 'upgrade-interactive', 'init', 'info', 'why', 'config', 'cache', 'dlx', 'exec', 'create', 'link', 'unlink', 'pack', 'publish', 'login', 'logout', 'set', 'version', 'workspace', 'workspaces', 'plugin', 'node', 'bin', 'global', 'audit', 'outdated', 'list', 'licenses', 'import', 'patch', 'patch-commit', 'rebuild', 'constraints', 'dedupe', 'explain', 'npm', 'search', 'stage', 'unplug', 'help', 'check', 'generate-lock-entry', 'owner', 'tag', 'team', 'policies', 'autoclean']);
const DIR_FLAGS = new Set(['--prefix', '-C', '--dir', '--cwd']);

const unquote = (t) => String(t ?? '').replace(/^["']|["']$/g, '');
const tokens = (seg) => [...(String(seg).trim().match(/"[^"]*"|'[^']*'|\S+/g) ?? [])];
const base = (t) => unquote(t).split(/[\\/]/).pop().toLowerCase().replace(/\.(?:cmd|exe|bat)$/, '');
const clip = (s) => String(s).slice(0, MAX_RUN_TEXT);

function defaultRead(p) {
  const st = fs.statSync(p);
  if (!st.isFile() || st.size > MAX_FILE) return null;
  const text = fs.readFileSync(p, 'utf8');
  return text.slice(0, 8192).includes('\u0000') ? null : text;
}

function safeRead(read, p) {
  try {
    return read(p);
  } catch {
    return null;
  }
}

function splitSegments(command) {
  return String(command ?? '').slice(0, 20_000).split(/\n|&&|\|\||;|\|/);
}

function strip(toks) {
  let t = toks;
  while (t.length && (WRAPPERS.has(base(t[0])) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(t[0]))) t = t.slice(1);
  return t;
}

function packageScripts(dir, read) {
  const text = safeRead(read, path.join(dir, 'package.json'));
  if (!text) return null;
  try {
    const scripts = JSON.parse(text)?.scripts;
    return scripts && typeof scripts === 'object' ? scripts : null;
  } catch {
    return null;
  }
}

function scriptRun(toks, cwd) {
  const runner = base(toks[0]);
  if (!['npm', 'pnpm', 'yarn', 'bun'].includes(runner)) return null;
  let dir = cwd;
  const rest = [];
  for (let i = 1; i < toks.length; i++) {
    if (DIR_FLAGS.has(toks[i]) && toks[i + 1]) {
      dir = path.resolve(cwd, unquote(toks[++i]));
      continue;
    }
    const eq = /^--(?:prefix|dir|cwd)=(.+)$/.exec(toks[i]);
    if (eq) {
      dir = path.resolve(cwd, unquote(eq[1]));
      continue;
    }
    if (toks[i] === '--') break;
    if (toks[i].startsWith('-')) continue;
    rest.push(unquote(toks[i]));
  }
  if (!rest.length) return null;
  const [verb, name] = rest;
  if (verb === 'run' || verb === 'run-script' || verb === 'rum' || verb === 'urn') return name ? { runner, dir, name, explicit: true } : null;
  if (runner === 'npm' || runner === 'pnpm' || runner === 'yarn') {
    if (NPM_SCRIPT_VERBS.has(verb)) return { runner, dir, name: verb === 't' || verb === 'tst' ? 'test' : verb, explicit: true };
  }
  if (runner === 'pnpm' && !PNPM_OWN.has(verb)) return { runner, dir, name: verb, explicit: false };
  if (runner === 'yarn' && !YARN_OWN.has(verb)) return { runner, dir, name: verb, explicit: false };
  return null;
}

function npmScriptTarget(run, read) {
  const scripts = packageScripts(run.dir, read);
  if (!scripts || typeof scripts[run.name] !== 'string') return null;
  const names = run.runner === 'npm' || run.runner === 'pnpm' ? [`pre${run.name}`, run.name, `post${run.name}`] : [run.name];
  const lines = names.filter((n) => typeof scripts[n] === 'string' && scripts[n].trim()).map((n) => `${n}: ${scripts[n]}`);
  return { kind: 'npm-script', name: run.name, path: path.join(run.dir, 'package.json'), text: clip(lines.join('\n')) };
}

function makeRun(toks, cwd) {
  if (!['make', 'gmake'].includes(base(toks[0]))) return null;
  let dir = cwd;
  let file = null;
  const targets = [];
  for (let i = 1; i < toks.length; i++) {
    const t = toks[i];
    if ((t === '-C' || t === '--directory') && toks[i + 1]) {
      dir = path.resolve(cwd, unquote(toks[++i]));
      continue;
    }
    if ((t === '-f' || t === '--file' || t === '--makefile') && toks[i + 1]) {
      file = unquote(toks[++i]);
      continue;
    }
    if (t.startsWith('-') || t.includes('=')) continue;
    targets.push(unquote(t));
  }
  return { dir, file, targets };
}

function makeRecipes(text, wanted) {
  const lines = String(text).split(/\r?\n/);
  const recipes = new Map();
  let current = null;
  let first = null;
  for (const line of lines) {
    if (/^\t/.test(line)) {
      if (current) for (const t of current) recipes.get(t).push(line.slice(1));
      continue;
    }
    if (!line.trim() || /^\s*#/.test(line)) continue;
    const m = /^([^:=#\t][^:=#]*?)\s*::?(?!=)/.exec(line);
    if (m) {
      current = m[1].trim().split(/\s+/).filter((t) => t && !t.includes('%'));
      for (const t of current) if (!recipes.has(t)) recipes.set(t, []);
      if (!first) first = current.find((t) => !t.startsWith('.')) ?? null;
      const inline = /;\s*(.+)$/.exec(line.slice(m[0].length));
      if (inline && current) for (const t of current) recipes.get(t).push(inline[1]);
    } else current = null;
  }
  const names = wanted.length ? wanted : first ? [first] : [];
  return names.filter((n) => recipes.get(n)?.length).map((n) => ({ name: n, text: recipes.get(n).join('\n') }));
}

function makeTargets(run, read) {
  const candidates = run.file ? [path.resolve(run.dir, run.file)] : ['GNUmakefile', 'makefile', 'Makefile'].map((f) => path.join(run.dir, f));
  for (const p of candidates) {
    const text = safeRead(read, p);
    if (text == null) continue;
    return makeRecipes(text, run.targets).map((r) => ({ kind: 'make', name: r.name, path: p, text: clip(r.text) }));
  }
  return [];
}

function scriptFile(toks, cwd, read) {
  const head = unquote(toks[0]);
  const name = base(head);
  let target = null;
  if (/^(?:\.{1,2}\/|\/|~\/)/.test(head) && !SHELLS.has(name)) target = head;
  else if (name === 'source' || name === '.') target = toks[1] ? unquote(toks[1]) : null;
  else if (SHELLS.has(name)) {
    for (let i = 1; i < toks.length; i++) {
      if (toks[i] === '-c') return null;
      if (toks[i].startsWith('-')) continue;
      target = unquote(toks[i]);
      break;
    }
  }
  if (!target || target.startsWith('~')) return null;
  const p = path.resolve(cwd, target);
  const text = safeRead(read, p);
  return text == null ? null : { kind: 'script', name: target, path: p, text: clip(text) };
}

export function runTargets(command, cwd, read = defaultRead) {
  const out = [];
  const seen = new Set();
  let dir = cwd || process.cwd();
  for (const seg of splitSegments(command)) {
    const toks = strip(tokens(seg));
    if (!toks.length) continue;
    if (base(toks[0]) === 'cd' || base(toks[0]) === 'pushd') {
      const to = unquote(toks[1] ?? '');
      if (to && to !== '-' && !to.startsWith('~') && !to.startsWith('$')) dir = path.resolve(dir, to);
      continue;
    }
    const found = [];
    const run = scriptRun(toks, dir);
    if (run) {
      const t = npmScriptTarget(run, read);
      if (t) found.push(t);
    }
    const make = makeRun(toks, dir);
    if (make) found.push(...makeTargets(make, read));
    if (!run && !make) {
      const t = scriptFile(toks, dir, read);
      if (t) found.push(t);
    }
    for (const t of found) {
      const key = `${t.kind}|${t.path}|${t.name}`;
      if (seen.has(key) || !t.text.trim()) continue;
      seen.add(key);
      out.push(t);
      if (out.length >= MAX_RUN_TARGETS) return out;
    }
  }
  return out;
}
