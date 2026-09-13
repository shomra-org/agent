import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { git, resolveOnPath, safeRef } from '../src/core/git-exec.mjs';

/**
 * A BRANCH NAME IS DATA, NEVER SHELL.
 *
 * `shomra pr` and `shomra provenance` built `git diff … ${base}...HEAD` as a
 * shell string, with `base` from `--base`, `GITHUB_BASE_REF` or the PR event.
 * `$(...)` is legal in a git ref, so a crafted branch name ran commands in the
 * CI job that holds the repository token.
 */

test('ordinary refs pass', () => {
  for (const r of ['main', 'develop', 'release/1.2', 'feature_x-y', 'v2.0.1']) assert.equal(safeRef(r), r);
});

test('shell metacharacters are refused', () => {
  for (const r of ['main$(touch /tmp/pwned)', 'main;id', 'main|sh', 'main`id`', 'a b', 'main&&id']) assert.equal(safeRef(r), null, r);
});

test('a ref that git would read as an option is refused', () => {
  assert.equal(safeRef('--output=/tmp/x'), null);
  assert.equal(safeRef('-c'), null);
});

test('refs git itself rejects are refused', () => {
  for (const r of ['a..b', 'x.lock', 'trailing/', 'trailing.', '', '   ']) assert.equal(safeRef(r), null, JSON.stringify(r));
});

test('git runs without a shell - a metacharacter in an argument is inert', () => {
  // Would create a file if a shell interpreted it; as argv it is just a bad revision.
  const out = git(['rev-parse', '--verify', '--quiet', 'HEAD$(echo pwned)'], { cwd: process.cwd() });
  assert.equal(out, null);
});

test('no command builds a git shell string from a variable', () => {
  for (const f of ['pr.mjs', 'provenance.mjs', 'secrets.mjs']) {
    const src = readFileSync(new URL(`../src/commands/${f}`, import.meta.url), 'utf8');
    assert.ok(!/execSync\(`git [^`]*\$\{/.test(src), `${f} interpolates into a git shell command`);
  }
});

/**
 * THE REPOSITORY BEING CHECKED NEVER SUPPLIES GIT.
 *
 * On Windows a bare `git` is searched for in the working directory before PATH
 * (cmd.exe for execSync, Node for execFileSync) - and the working directory is
 * the repository under check. A committed `git.bat` ran inside CI.
 */
const planted = mkdtempSync(join(tmpdir(), 'shomra-planted-git-'));
process.on('exit', () => rmSync(planted, { recursive: true, force: true }));
writeFileSync(join(planted, 'git.bat'), '@echo PLANTED\r\n');
writeFileSync(join(planted, 'git.cmd'), '@echo PLANTED\r\n');
if (process.platform === 'win32') {
  // node.exe renamed: a real executable whose `--version` is not a git version.
  copyFileSync(process.execPath, join(planted, 'git.exe'));
} else {
  writeFileSync(join(planted, 'git'), '#!/bin/sh\necho PLANTED\n');
  chmodSync(join(planted, 'git'), 0o755);
}

test('git is never resolved from the working directory or a relative PATH entry', () => {
  const cwd = process.cwd();
  process.chdir(planted);
  try {
    const delim = process.platform === 'win32' ? ';' : ':';
    assert.equal(resolveOnPath('git', { PATH: ['.', '', 'relative/bin'].join(delim) }), null);
  } finally {
    process.chdir(cwd);
  }
});

test('with a git planted in the repository, the git that runs is the one on PATH', { skip: !resolveOnPath('git') && 'no git on PATH' }, () => {
  // A child with the Windows default (no NoDefaultCurrentDirectoryInExePath), so the planted file WOULD win a bare lookup.
  const env = { ...process.env };
  delete env.NoDefaultCurrentDirectoryInExePath;
  const script = `import { git } from ${JSON.stringify(new URL('../src/core/git-exec.mjs', import.meta.url).href)};
process.stdout.write(String(git(['--version'], { cwd: ${JSON.stringify(planted)} })));`;
  const out = execFileSync(process.execPath, ['--input-type=module', '-e', script], { env, cwd: planted }).toString();
  assert.match(out, /git version/);
  assert.doesNotMatch(out, /PLANTED/);
});

test('no source file runs git through a shell string or a bare name', () => {
  const offenders = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p);
      else if (p.endsWith('.mjs') && !p.endsWith('git-exec.mjs')) {
        const src = readFileSync(p, 'utf8');
        if (/exec(Sync)?\(\s*[`'"]git\b|exec(File)?(Sync)?\(\s*['"`]git['"`]|spawn(Sync)?\(\s*['"`]git['"`]/.test(src)) offenders.push(p);
      }
    }
  };
  walk(new URL('../src', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
  assert.deepEqual(offenders, []);
});
