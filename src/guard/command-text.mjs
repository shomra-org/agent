/**
 * WHICH TEXT IS THE COMMAND, AND WHICH TEXT IS THE PATCH - one place for both
 * `classify.mjs` (the send decision) and `memory-write.mjs` (the post-edit
 * rebuild), so the two can never disagree about what a call carries. Mirrors
 * the server's `argvCommand` / `shellCommandText` / `patchPayloadOf`
 * (`subject-wiring.ts`); the backend's `test/gate/subject-wiring-bench` runs
 * both on the same inputs.
 */

const SHELL_BIN = /^(?:.*[\\/])?(?:(?:ba|z|da|k|fi|a)?sh|pwsh|powershell|cmd)(?:\.exe)?$/i;
const POSIX_SCRIPT_FLAG = /^-[a-z]*c[a-z]*$/;
const REST_SCRIPT_FLAG = /^(?:\/[ck]|-command|-c)$/i;

function quoteArg(a) {
  if (a === '') return "''";
  return /[\s'"\\$`|&;<>()*?!#~{}[\]]/.test(a) ? `'${a.split("'").join("'\\''")}'` : a;
}

/**
 * ⚠ AN ARGV IS NOT A COMMAND LINE. Codex sends `["bash","-lc","npm i x"]`;
 * joined with spaces the installer became an argument of `bash`. The script a
 * shell is told to run IS the command; any other argv is re-quoted.
 */
export function argvCommand(argv) {
  const a = (Array.isArray(argv) ? argv : []).filter((x) => typeof x === 'string' || typeof x === 'number').map(String);
  if (!a.length) return '';
  if (a.length >= 3 && SHELL_BIN.test(a[0])) {
    const bin = a[0].replace(/^.*[\\/]/, '').toLowerCase();
    const posix = !/^(?:cmd|pwsh|powershell)(?:\.exe)?$/.test(bin);
    for (let i = 1; i < a.length - 1; i++) {
      if (posix && POSIX_SCRIPT_FLAG.test(a[i])) return a[i + 1];
      if (!posix && REST_SCRIPT_FLAG.test(a[i])) return a.slice(i + 1).join(' ');
    }
  }
  return a.map(quoteArg).join(' ');
}

const COMMAND_KEYS = ['command', 'cmd', 'script', 'commandLine', 'command_line', 'cmdline'];

/** The command a shell-shaped call runs, whichever key and shape carries it. */
export function shellCommandOf(input = {}) {
  const i = input ?? {};
  for (const key of COMMAND_KEYS) {
    const v = i[key];
    if (Array.isArray(v)) return argvCommand(v);
    if (typeof v === 'string' && v.trim()) {
      return Array.isArray(i.args) && i.args.length && !/\s/.test(v.trim()) ? argvCommand([v, ...i.args]) : v;
    }
  }
  return Array.isArray(i.argv) ? argvCommand(i.argv) : '';
}

/**
 * ⚠ `apply_patch <<'EOF' … EOF` INSIDE A SHELL SCRIPT IS A PATCH TOO. Codex
 * runs `bash -lc "apply_patch <<'EOF' …"` as often as it sends the argv form,
 * and only argv[0] was recognised - the heredoc patch reached nobody.
 */
export function heredocPatch(script) {
  const s = String(script ?? '');
  const m = /(?:^|[\s;&|(])apply_patch\s+<<-?\s*(['"]?)([A-Za-z_][\w-]*)\1[ \t]*\r?\n([\s\S]*?)\r?\n[ \t]*\2[ \t]*(?:\r?\n|$)/.exec(s);
  if (m && /^\*\*\* (?:Begin Patch|Add File:|Update File:)/m.test(m[3])) return m[3];
  const inline = /(?:^|[\s;&|(])apply_patch\s+(['"])(\*\*\* Begin Patch[\s\S]*?\*\*\* End Patch)\1/.exec(s);
  return inline ? inline[2] : '';
}

const isApplyPatchArgv = (argv) => Array.isArray(argv) && /(?:^|[\\/])apply_patch$/.test(String(argv[0] ?? '')) && typeof argv[1] === 'string';

/**
 * Codex's patch in every shape it arrives in: `{ patch }`, `{ input }`, argv
 * `["apply_patch", "<patch>"]`, a heredoc in a shell script, or a unified diff.
 */
export function patchTextOf(tool, input = {}) {
  const i = input ?? {};
  if (typeof i.patch === 'string') return i.patch;
  const argv = Array.isArray(i.command) ? i.command : Array.isArray(i.argv) ? i.argv : null;
  if (isApplyPatchArgv(argv)) return argv[1];
  if (/^apply_patch$/i.test(String(tool ?? ''))) {
    if (typeof i.input === 'string') return i.input;
    if (typeof i.command === 'string' && /^\*\*\* Begin Patch/m.test(i.command)) return i.command;
  }
  const inScript = heredocPatch(shellCommandOf(i));
  if (inScript) return inScript;
  if (typeof i.diff === 'string') return i.diff;
  return '';
}
