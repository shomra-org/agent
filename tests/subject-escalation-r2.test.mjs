import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';

import { WRITE_TOOLS, guardNeedsServer } from '../src/guard/classify.mjs';
import { heredocPatch, patchTextOf } from '../src/guard/command-text.mjs';
import { commandSubjectTypes, normalizeCommand, pathSubjectTypes, shellWriteTargets, subjectTypesTtlMs } from '../src/guard/subject-preclassify.mjs';
import { postEditContents } from '../src/guard/memory-write.mjs';
import { normalizeGuardInput } from '../src/guard/normalize.mjs';
import { TOOL_GUARD_MATCHERS, widenToolGuardMatcher } from '../src/agents/installers.mjs';

/**
 * The end-to-end red team's cases, pinned. Each one was a call the endpoint
 * either decided alone or described wrongly to the server.
 */

const read = (files) => (p) => {
  const hit = Object.entries(files).find(([k]) => path.resolve(k) === path.resolve(p));
  if (!hit) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
  return hit[1];
};
const MULTI = 'FROM node:20 AS build\nUSER node\nRUN x\nFROM node:20 AS runtime\nUSER node\nCMD y\n';
const patchOf = (body) => `*** Begin Patch\n*** Update File: Dockerfile\n${body}\n*** End Patch`;

test('apply_patch honours the @@ anchor - the RUNTIME stage is rebuilt, not the build stage', () => {
  const [d] = postEditContents('apply_patch', { input: patchOf('@@ FROM node:20 AS runtime\n-USER node\n+USER root') }, { cwd: '/p', read: read({ '/p/Dockerfile': MULTI }) });
  assert.equal(d.content, MULTI.replace('AS runtime\nUSER node', 'AS runtime\nUSER root'));
});

test('an ambiguous block, a missing anchor and a non-unique old_string send NOTHING', () => {
  const r = read({ '/p/Dockerfile': MULTI });
  assert.deepEqual(postEditContents('apply_patch', { input: patchOf('@@\n-USER node\n+USER root') }, { cwd: '/p', read: r }), []);
  assert.deepEqual(postEditContents('apply_patch', { input: patchOf('@@ FROM nope\n-USER node\n+USER root') }, { cwd: '/p', read: r }), []);
  assert.deepEqual(postEditContents('Edit', { file_path: 'Dockerfile', old_string: 'USER node', new_string: 'USER root' }, { cwd: '/p', read: r }), [], 'Claude refuses a non-unique old_string');
  const all = postEditContents('Edit', { file_path: 'Dockerfile', old_string: 'USER node', new_string: 'USER root', replace_all: true }, { cwd: '/p', read: r });
  assert.equal(all[0].content.includes('USER node'), false);
});

test('rebuild edge cases: CRLF, End of File, Move to, an Edit creating a file', () => {
  const r = read({ '/p/crlf/Dockerfile': 'FROM a\r\nUSER node\r\nCMD y\r\n', '/p/Dockerfile': 'CMD y\nX\nCMD y\n' });
  assert.equal(postEditContents('Edit', { file_path: 'crlf/Dockerfile', old_string: 'USER node\nCMD y', new_string: 'USER root\nCMD y' }, { cwd: '/p', read: r })[0].content, 'FROM a\r\nUSER root\r\nCMD y\r\n');
  assert.equal(postEditContents('apply_patch', { input: patchOf('@@\n-CMD y\n+CMD z\n*** End of File') }, { cwd: '/p', read: r })[0].content, 'CMD y\nX\nCMD z\n');
  const mv = postEditContents('apply_patch', { input: '*** Begin Patch\n*** Update File: crlf/Dockerfile\n*** Move to: deploy/Dockerfile\n@@\n-USER node\n+USER root\n*** End Patch' }, { cwd: '/p', read: r });
  assert.equal(mv[0].path, 'deploy/Dockerfile');
  assert.equal(postEditContents('Edit', { file_path: 'new/Dockerfile', old_string: '', new_string: 'FROM x' }, { cwd: '/p', read: r })[0].content, 'FROM x');
});

test('a heredoc apply_patch inside a shell script is a patch; Codex hooks carry it in command', () => {
  const patch = '*** Begin Patch\n*** Add File: compose.yaml\n+services: {}\n*** End Patch';
  const script = ['cd x && apply_patch <<', "'", 'EOF', "'", '\n', patch, '\n', 'EOF', '\n'].join('');
  assert.equal(heredocPatch(script), patch);
  assert.equal(patchTextOf('shell', { command: ['bash', '-lc', script] }), patch);
  assert.equal(patchTextOf('apply_patch', { command: patch }), patch);
  assert.equal(guardNeedsServer('shell', { command: ['bash', '-lc', script] }, false, { subjectTypes: ['container'] }), true);
});

test('binaries are matched by basename; PowerShell write cmdlets are writes', () => {
  assert.equal(normalizeCommand('npm.cmd install x'), 'npm install x');
  assert.match(normalizeCommand('& "C:\\Program Files\\Docker\\docker.exe" run nginx'), /docker" run nginx|docker run nginx/);
  assert.equal(normalizeCommand('pip3.12 install x'), 'pip install x');
  for (const c of ['npm.cmd install x', 'docker.exe run --privileged nginx', 'pip3.12 install x', 'python3.11 -m pip install x']) assert.ok(commandSubjectTypes(c).size, c);
  assert.deepEqual(shellWriteTargets('Set-Content -Path Dockerfile -Value "FROM node:latest"'), [{ path: 'Dockerfile', text: 'FROM node:latest' }]);
  assert.equal(shellWriteTargets('"FROM x" | Out-File Dockerfile')[0].path, 'Dockerfile');
  assert.equal(guardNeedsServer('PowerShell', { command: 'Add-Content package.json "x"' }, false, { subjectTypes: ['package'] }), true);
});

test('precision: YAML and Python escalate only when their text says so; running a script is not writing it', () => {
  assert.equal(pathSubjectTypes('notes/config.yaml', 'title: hello\nitems: [a]\n').size, 0);
  assert.ok(pathSubjectTypes('app.yaml', 'apiVersion: v1\nkind: Pod\n').has('image'));
  assert.ok(pathSubjectTypes('compose.yaml', null).has('container'), 'a known name needs no sniff');
  assert.equal(pathSubjectTypes('src/app.py', 'print(1)').size, 0);
  assert.ok(pathSubjectTypes('src/app.py', 'AutoModel.from_pretrained("x/y")').has('model'));
  assert.equal(guardNeedsServer('Bash', { command: 'python scripts/train.py' }, false, { subjectTypes: ['model'] }), false);
  assert.equal(guardNeedsServer('Write', { file_path: 'docs/a.yaml', content: 'title: x' }, false, { subjectTypes: ['image'] }), false);
});

test('Cursor stdio MCP keeps the tool input; Windsurf edits[] become a MultiEdit', () => {
  const c = normalizeGuardInput('cursor', { hook_event_name: 'beforeMCPExecution', tool_name: 'execute_command', tool_input: '{"command":"docker run --privileged nginx"}', command: 'npx -y @wonderwhy-er/desktop-commander' });
  assert.equal(c.tool_name, 'mcp__cursor__execute_command');
  assert.match(c.tool_input.command, /privileged/);
  const sh = normalizeGuardInput('cursor', { hook_event_name: 'beforeShellExecution', command: 'npm i x' });
  assert.equal(sh.tool_name, 'Bash');
  const w = normalizeGuardInput('windsurf', { agent_action_name: 'pre_write_code', tool_info: { file_path: '/p/package.json', edits: [{ old_string: 'a', new_string: 'b' }] } });
  assert.equal(w.tool_name, 'MultiEdit');
  assert.equal(w.tool_input.edits.length, 1);
});

test('installer matchers name PowerShell and Codex apply_patch, and an existing install is widened', () => {
  assert.match(TOOL_GUARD_MATCHERS.claude, /\bPowerShell\b/);
  assert.match(TOOL_GUARD_MATCHERS.codex, /\bapply_patch\b/);
  const pre = [{ matcher: 'Bash|Write|Edit|MultiEdit|NotebookEdit|mcp__.*|MyTool', hooks: [{ type: 'command', command: 'npx -y @shomra/agent tool-guard --agent claude' }] }];
  assert.equal(widenToolGuardMatcher(pre, TOOL_GUARD_MATCHERS.claude), true);
  assert.match(pre[0].matcher, /\bPowerShell\b/);
  assert.match(pre[0].matcher, /MyTool/, 'a user-added name is kept');
  assert.equal(widenToolGuardMatcher(pre, TOOL_GUARD_MATCHERS.claude), false, 'idempotent');
  const other = [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'some-other-hook' }] }];
  assert.equal(widenToolGuardMatcher(other, TOOL_GUARD_MATCHERS.claude), false, 'another hook is not touched');
});

test('an empty learned set expires in 60 s, a non-empty one in 10 min', () => {
  const prev = process.env.SHOMRA_GUARD_SUBJECT_TTL_MS;
  delete process.env.SHOMRA_GUARD_SUBJECT_TTL_MS;
  try {
    assert.equal(subjectTypesTtlMs([]), 60_000);
    assert.equal(subjectTypesTtlMs(['package']), 600_000);
  } finally {
    if (prev !== undefined) process.env.SHOMRA_GUARD_SUBJECT_TTL_MS = prev;
  }
});

test('Copilot / VS Code write tools are writes, with their camelCase keys', () => {
  for (const t of ['edit', 'create', 'replace_string_in_file', 'insert_edit_into_file']) assert.ok(WRITE_TOOLS.has(t), t);
  const r = read({ '/p/package.json': '{"a":1}' });
  assert.equal(postEditContents('replace_string_in_file', { filePath: 'package.json', oldString: '"a":1', newString: '"a":2' }, { cwd: '/p', read: r })[0].content, '{"a":2}');
});
