import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { bold, dim, green, red, yellow } from '../core/terminal.mjs';

export async function cmdInstallPrecommit(flags, positional) {

  if (flags['pre-receive']) return installPreReceive(flags, positional);
  const root = path.resolve(positional[0] || '.');
  const hooksDir = gitHooksDir(root);
  if (!hooksDir) {
    console.error(red('✗') + ' Not a git repository (or git unavailable). cd into your repo first.');
    process.exit(EXIT_USAGE);
  }
  const hookPath = path.join(hooksDir, 'pre-commit');
  const marker = 'shomra check --staged';
  const managed = [
    '#!/bin/sh',
    '# Shomra - block staged AI artifacts that fail the gate before they land.',
    '# Managed by `shomra install-precommit`. Delete this file to uninstall.',

    'command -v shomra >/dev/null 2>&1 || {',
    '  echo "" >&2',
    '  echo "!! ============================================================== !!" >&2',
    '  echo "!!  WARNING: shomra not on PATH - the AI-artifact gate DID NOT RUN !!" >&2',
    '  echo "!!  Staged MCP/skill/rules files were committed UNGATED.          !!" >&2',
    '  echo "!!  Fix: npm i -g @shomra/agent   (then re-commit to gate)        !!" >&2',
    '  echo "!! ============================================================== !!" >&2',
    '  echo "" >&2',
    '  exit 0',
    '}',
    'shomra check --staged',
    'if [ "$?" -eq 1 ]; then',
    '  echo "✗ Shomra blocked a staged AI artifact - run: shomra fix <file> --apply  (or: git commit --no-verify to override)"',
    '  exit 1',
    'fi',
    'exit 0',
    '',
  ].join('\n');

  let existing = null;
  try {
    existing = fs.readFileSync(hookPath, 'utf8');
  } catch {}

  if (existing && existing.includes(marker) && !flags.force) {
    console.log(green('  ✓') + ' Shomra pre-commit hook already installed ' + dim('→ ' + hookPath));
    return;
  }
  if (existing && !existing.includes(marker) && !flags.force) {
    console.log('\n  ' + yellow('⚠') + ' A pre-commit hook already exists ' + dim('→ ' + hookPath));
    console.log('  Add this line to it, or re-run with ' + bold('--force') + ' to replace it (a backup is kept):');
    console.log('    ' + bold(marker) + '\n');
    return;
  }
  if (existing && flags.force) {
    try {
      fs.writeFileSync(hookPath + '.bak', existing);
      console.log(dim('  Backed up existing hook → ' + path.basename(hookPath) + '.bak'));
    } catch {}
  }
  fs.writeFileSync(hookPath, managed, 'utf8');
  try {
    fs.chmodSync(hookPath, 0o755);
  } catch {}
  console.log('\n  ' + green('✓ Installed') + ' Shomra pre-commit hook ' + dim('→ ' + hookPath));
  console.log(dim('  Staged AI artifacts are now gated on every commit. Override once with ') + bold('git commit --no-verify') + dim('.\n'));
}

function installPreReceive(flags, positional) {
  const root = path.resolve(positional[0] || flags.path || '.');

  const bareHooks = path.join(root, 'hooks');
  const dir = fs.existsSync(bareHooks) && fs.statSync(bareHooks).isDirectory() ? bareHooks : gitHooksDir(root);
  if (!dir) {
    console.error(red('✗') + ` No git hooks directory under ${root}. Point this at a BARE repository (the one the server hosts), not a working checkout.`);
    process.exit(EXIT_USAGE);
  }

  const hookPath = path.join(dir, 'pre-receive');
  const marker = 'shomra gate --all';
  const managed = [
    '#!/bin/sh',
    '# Shomra - refuse a push that carries a blocked AI artifact.',
    '# Managed by `shomra install-precommit --pre-receive`. Delete this file to uninstall.',
    '#',
    '# Runs on the SERVER, so unlike pre-commit it cannot be skipped with',
    '# --no-verify and it covers developers who never installed anything.',
    'set -e',
    '',
    '# ⚠ FAIL CLOSED. The client-side hook fails open on a missing binary because',
    '# blocking a local commit over a tooling problem is hostile. The opposite is',
    '# true here: this is the enforcement point, so an environment that cannot run',
    '# the check must refuse the push rather than wave it through - otherwise',
    '# deleting the binary is the bypass.',
    'command -v shomra >/dev/null 2>&1 || {',
    '  echo "" >&2',
    '  echo "REJECTED: shomra is not installed on this git server, so the AI-artifact" >&2',
    '  echo "          gate could not run. Install it (npm i -g @shomra/agent) or" >&2',
    '  echo "          remove this hook deliberately." >&2',
    '  exit 1',
    '}',
    '',
    'TMP=$(mktemp -d)',
    'trap \'rm -rf "$TMP"\' EXIT',
    'STATUS=0',
    '',
    '# stdin is "<old> <new> <ref>" per pushed ref. Export each ref\'s tree to a',
    '# temp dir and gate it - the push is refused as a whole if any ref carries a',
    '# blocked artifact.',
    'while read -r oldrev newrev refname; do',
    '  # All-zero newrev = branch deletion. Nothing arrives, nothing to gate.',
    '  case "$newrev" in *[!0]*) ;; *) continue ;; esac',
    '  WORK="$TMP/$(echo "$refname" | tr "/" "_")"',
    '  mkdir -p "$WORK"',
    '  git archive "$newrev" | tar -x -C "$WORK" 2>/dev/null || continue',
    '  if ! shomra gate --all "$WORK"; then',
    '    echo "" >&2',
    '    echo "REJECTED: $refname carries an AI artifact Shomra blocks (see above)." >&2',
    '    echo "          Fix it locally (shomra check --fix) and push again." >&2',
    '    STATUS=1',
    '  fi',
    'done',
    '',
    'exit $STATUS',
    '',
  ].join('\n');

  let existing = null;
  try { existing = fs.readFileSync(hookPath, 'utf8'); } catch {  }
  if (existing && existing.includes(marker) && !flags.force) {
    console.log(green('  ✓') + ' Shomra pre-receive hook already installed ' + dim('→ ' + hookPath));
    return;
  }
  if (existing && !existing.includes(marker) && !flags.force) {
    console.log('\n  ' + yellow('⚠') + ' A pre-receive hook already exists ' + dim('→ ' + hookPath));
    console.log('  Chain Shomra into it, or re-run with ' + bold('--force') + ' to replace it (a backup is kept).\n');
    return;
  }
  if (existing && flags.force) {
    try { fs.writeFileSync(hookPath + '.bak', existing); console.log(dim('  Backed up existing hook → pre-receive.bak')); } catch {  }
  }
  fs.writeFileSync(hookPath, managed, 'utf8');
  try { fs.chmodSync(hookPath, 0o755); } catch {  }

  console.log('\n  ' + green('✓ Installed') + ' Shomra pre-receive hook ' + dim('→ ' + hookPath));
  console.log(dim('  Every push is now gated server-side - no --no-verify, and no per-developer install.'));
  console.log(dim('  This hook FAILS CLOSED: if shomra is missing on the server, pushes are refused.'));
  console.log(dim('  GitHub.com has no server-side hooks - there, use the Action as a required status check.\n'));
}

function gitHooksDir(root) {
  try {
    const dir = execSync('git rev-parse --git-path hooks', { cwd: root, stdio: ['ignore', 'pipe', 'ignore'], timeout: 3000 }).toString().trim();
    if (!dir) return null;
    const abs = path.isAbsolute(dir) ? dir : path.join(root, dir);
    fs.mkdirSync(abs, { recursive: true });
    return abs;
  } catch {
    return null;
  }
}
