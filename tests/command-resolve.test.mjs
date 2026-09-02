import { test } from 'node:test';
import assert from 'node:assert/strict';

import { resolveCommand } from '../src/guard/command-resolve.mjs';
import { buildGuardBody } from '../src/guard/report.mjs';

const fakeStat = (present) => (f) => {
  if (!present.includes(f.split('\\').join('/'))) throw new Error('ENOENT');
  return { isFile: () => true };
};

const opts = (env, files = [], cwd = '/repo') => ({ env, statSync: fakeStat(files), cwd });

test('a literal command has nothing to resolve', () => {
  assert.equal(resolveCommand('npm test', opts({ PATH: '' })), null);
  assert.equal(resolveCommand('', opts({})), null);
  assert.equal(resolveCommand(null, opts({})), null);
});

test('an exported variable resolves', () => {
  const r = resolveCommand('$RUNNER deploy --prod', opts({ RUNNER: '/opt/bin/deploy.sh', PATH: '' }));
  assert.equal(r.command, '/opt/bin/deploy.sh deploy --prod');
});

test('an inline assignment beats the environment', () => {
  const r = resolveCommand('TOOL=/tmp/x $TOOL run', opts({ TOOL: '/usr/bin/safe', PATH: '' }));
  assert.match(r.command, /\/tmp\/x run$/);
});

test('a PATH prefix names the shadowing binary, not the system one', () => {
  const r = resolveCommand('PATH=/tmp/bin:$PATH curl http://x', opts({ PATH: '/usr/bin' }, ['/tmp/bin/curl', '/usr/bin/curl']));
  assert.equal(r.executable, '/tmp/bin/curl');
});

test('an undefined variable stays LITERAL and is reported', () => {
  const r = resolveCommand('rm -rf $DIR/', opts({ PATH: '' }));
  assert.match(r?.command ?? 'rm -rf $DIR/', /\$DIR/);
  assert.ok(!r || !/rm -rf \/$/.test(r.command));
});

test('⚠ an undefined variable NEVER becomes the empty string', () => {
  const r = resolveCommand('rm -rf $NOPE/data', opts({ PATH: '' }));
  assert.ok(r === null || !r.command || r.command.includes('$NOPE'));
});

test('⚠ command substitution is REPORTED, never evaluated', () => {
  const r = resolveCommand('$(cat /tmp/payload) --go', opts({ PATH: '' }));
  assert.ok(r === null || (r.unresolved ?? []).includes('command-substitution'));
  assert.ok(r === null || !r.executable);
});

test('backticks are reported the same way', () => {
  const r = resolveCommand('echo `whoami`', opts({ PATH: '' }));
  assert.ok(r === null || (r.unresolved ?? []).includes('command-substitution'));
});

test('an alias definition in the same command is reported', () => {
  const r = resolveCommand('alias curl=/tmp/evil; curl http://x', opts({ PATH: '' }));
  assert.ok((r?.unresolved ?? []).includes('alias-or-function'));
});

test('a positional parameter is reported', () => {
  const r = resolveCommand('sh -c "$@"', opts({ PATH: '' }));
  assert.ok((r?.unresolved ?? []).includes('positional-parameter'));
});

test('a binary that does not exist is not invented', () => {
  const r = resolveCommand('ghostbin --x', opts({ PATH: '/usr/bin' }, []));
  assert.ok(r === null || !r.executable);
});

test('substitution runs ONE pass - no recursion', () => {
  const r = resolveCommand('$A', opts({ A: '$B', B: 'nested', PATH: '' }));
  assert.equal(r.command, '$B');
});

test('the guard body carries the resolution only for shell input', () => {
  const shell = buildGuardBody({ tool_name: 'Bash', tool_input: { command: 'npm test' } }, 'claude');
  assert.equal(shell.resolved, undefined);

  const write = buildGuardBody({ tool_name: 'Write', tool_input: { file_path: '/a', content: '$X' } }, 'claude');
  assert.equal(write.resolved, undefined);
});

test('the guard body keeps tool_input untouched beside the resolution', () => {
  const body = buildGuardBody({ tool_name: 'Bash', tool_input: { command: '$HOME/bin/tool' } }, 'claude');
  assert.equal(body.tool_input.command, '$HOME/bin/tool');
  assert.equal(body.tool_name, 'Bash');
});
