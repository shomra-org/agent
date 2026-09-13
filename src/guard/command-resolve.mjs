import fs from 'node:fs';
import path from 'node:path';

const MAX_LEN = 16 * 1024;
const MAX_UNRESOLVED = 8;
const MAX_PATH_ENTRIES = 64;

const ASSIGN_PREFIX = /^\s*([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|\S*)\s+/;
const VAR_RE = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g;
const SUBST_RE = /\$\([^)]*\)|`[^`\n]*`/;
const POSITIONAL_RE = /\$[@*#?$0-9]/;
const INDIRECTION = /[$`]/;
const ALIAS_OR_FUNCTION = /(?:^|[\s;&|(])(?:alias\s+[A-Za-z_][\w-]*\s*=|function\s+[A-Za-z_][\w-]*\s*(?:\(\s*\))?\s*\{|[A-Za-z_][\w-]*\s*\(\s*\)\s*\{)/;

function unquote(v) {
  const s = String(v ?? '');
  if (s.length >= 2 && ((s[0] === '"' && s.endsWith('"')) || (s[0] === "'" && s.endsWith("'")))) return s.slice(1, -1);
  return s;
}

function inlineAssignments(command) {
  const vars = new Map();
  let rest = command;
  for (let m = ASSIGN_PREFIX.exec(rest); m; m = ASSIGN_PREFIX.exec(rest)) {
    vars.set(m[1], unquote(m[2]));
    rest = rest.slice(m[0].length);
  }
  return { vars, rest };
}

/**
 * ⚠ A VARIABLE NOBODY DEFINED STAYS LITERAL AND IS REPORTED UNRESOLVED. Letting
 * it fall through to the empty string is how `rm -rf $DIR/` becomes `rm -rf /`
 * and gets screened as the second one. Absence is reported, never substituted.
 */
function substitute(text, vars, env, unresolved) {
  return text.replace(VAR_RE, (whole, braced, bare) => {
    const name = braced || bare;
    if (vars.has(name)) return vars.get(name);
    const fromEnv = env?.[name];
    if (typeof fromEnv === 'string' && fromEnv.length) return fromEnv;
    if (unresolved.length < MAX_UNRESOLVED && !unresolved.includes(whole)) unresolved.push(whole);
    return whole;
  });
}

function isExecutable(file, statSync) {
  try {
    const st = statSync(file);
    return st.isFile();
  } catch {
    return false;
  }
}

/**
 * PATH as the shell running the command splits it.
 *
 * ⚠ The commands screened here are shell text - bash, or Git Bash on Windows -
 * where `PATH=/tmp/bin:$PATH` is colon-separated. Splitting on the HOST's
 * delimiter read that on Windows as one directory named `/tmp/bin:/usr/bin`, so
 * the shadowing binary the prefix planted was never found and the report named
 * nothing. A `$PATH` substituted from a Windows environment adds `;` and drive
 * letters, so: split on `;`, and on `:` except the one after a drive letter.
 */
function pathEntries(value) {
  const out = [];
  let cur = '';
  for (const ch of String(value ?? '')) {
    if (ch === ';' || (ch === ':' && !/^[A-Za-z]$/.test(cur))) {
      if (cur) out.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  if (cur) out.push(cur);
  return out.slice(0, MAX_PATH_ENTRIES);
}

const windowsStyle = (p) => /^[A-Za-z]:[\\/]/.test(p) || p.includes('\\');
const flavour = (p) => (windowsStyle(p) ? path.win32 : path.posix);

function locate(word, effectivePath, cwd, statSync) {
  if (!word) return null;
  const base = cwd || '.';
  if (word.includes('/') || word.includes('\\')) {
    const abs = flavour(word).isAbsolute(word) ? word : flavour(base).join(base, word);
    return isExecutable(abs, statSync) ? abs : null;
  }
  for (const dir of pathEntries(effectivePath)) {
    // A relative entry (`.`, `bin`) is relative to where the COMMAND runs - which is how it shadows.
    const at = flavour(dir).isAbsolute(dir) ? dir : flavour(base).join(base, dir);
    const candidate = flavour(at).join(at, word);
    if (isExecutable(candidate, statSync)) return candidate;
  }
  return null;
}

/**
 * What this command's indirection points at, resolved from the environment and
 * the filesystem this machine actually has - the two things the server does not
 * hold and no pattern can recover from the string.
 *
 *  IT NEVER EXECUTES ANYTHING. `$(…)` and backticks are REPORTED unresolved,
 * never evaluated: running attacker-influenced text in order to screen it is the
 * vulnerability, not the control. Same reason the scanner resolves an MCP source
 * without launching it.
 *
 * ⚠ The result CLEARS NOTHING server-side. It is evidence the backend screens
 * with the same detectors it ran on the literal text, and it may only ever add.
 */
export function resolveCommand(command, opts = {}) {
  const cmd = typeof command === 'string' ? command.slice(0, MAX_LEN) : '';
  if (!cmd.trim()) return null;

  const env = opts.env ?? process.env;
  const statSync = opts.statSync ?? fs.statSync;
  const cwd = opts.cwd ?? env.PWD ?? process.cwd();

  if (!INDIRECTION.test(cmd) && !ALIAS_OR_FUNCTION.test(cmd)) return null;

  const unresolved = [];
  if (SUBST_RE.test(cmd)) unresolved.push('command-substitution');
  if (POSITIONAL_RE.test(cmd)) unresolved.push('positional-parameter');
  if (ALIAS_OR_FUNCTION.test(cmd)) unresolved.push('alias-or-function');

  const { vars, rest } = inlineAssignments(cmd);
  const resolved = substitute(cmd, vars, env, unresolved);

  const effectivePath = vars.has('PATH') ? substitute(vars.get('PATH'), vars, env, []) : env.PATH;
  const word = substitute(rest, vars, env, []).trim().split(/\s+/)[0] ?? '';
  const executable = SUBST_RE.test(word) || word.includes('$') ? null : locate(word, effectivePath, cwd, statSync);

  if (resolved === cmd && !executable && !unresolved.length) return null;
  return {
    ...(resolved === cmd ? {} : { command: resolved }),
    ...(executable ? { executable } : {}),
    ...(unresolved.length ? { unresolved } : {}),
  };
}
