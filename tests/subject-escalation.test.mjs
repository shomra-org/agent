import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';


import { SHELL_TOOL_NAMES, SHELL_TOOLS_RE, argvCommand, callSubjectTypes, guardNeedsServer, shellCommandOf } from '../src/guard/classify.mjs';
import { commandSubjectTypes, pathSubjectTypes, readSubjectTypes, rememberSubjectTypes, serverScreened, subjectEscalation } from '../src/guard/subject-preclassify.mjs';
import { postEditContents } from '../src/guard/memory-write.mjs';
import { normalizeGuardInput } from '../src/guard/normalize.mjs';
import { postContentField } from '../src/guard/tool-guard.mjs';

const read = (files) => (p) => {
  const hit = Object.entries(files).find(([k]) => path.resolve(k) === path.resolve(p));
  if (!hit) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
  return hit[1];
};

test('every vendor shell tool is a shell tool', () => {
  for (const t of ['Bash', 'PowerShell', 'local_shell', 'exec_command', 'container.exec', 'run_in_terminal', 'run_terminal_command',
    'builtin_run_terminal_command', 'developer__shell', 'execute_bash', 'executeBash', 'run_shell_command']) {
    assert.ok(SHELL_TOOLS_RE.test(t), t);
  }
  assert.equal(SHELL_TOOLS_RE.test('containerXexec'), false, 'the dot is literal');
  assert.equal(SHELL_TOOL_NAMES.length, new Set(SHELL_TOOL_NAMES).size);
});

test('the shell tool list matches the server’s SHELL_TOOL_NAMES', { skip: !fs.existsSync(new URL('../../Dragox.Backend/src/modules/runtime/gate/domain/tool-guard-grading.ts', import.meta.url)) }, () => {
  const src = fs.readFileSync(new URL('../../Dragox.Backend/src/modules/runtime/gate/domain/tool-guard-grading.ts', import.meta.url), 'utf8');
  const lit = /SHELL_TOOL_NAMES: readonly string\[\] = \[([\s\S]*?)\];/.exec(src);
  const server = new Set([...(lit?.[1] ?? '').matchAll(/'([^']+)'/g)].map((m) => m[1]));
  assert.deepEqual([...server].sort(), [...SHELL_TOOL_NAMES].sort());
});

test('an argv is unwrapped to the script it runs', () => {
  assert.equal(argvCommand(['bash', '-lc', 'npm i left-pad']), 'npm i left-pad');
  assert.equal(argvCommand(['/bin/zsh', '-c', 'pip install x', 'arg0']), 'pip install x');
  assert.equal(argvCommand(['powershell', '-Command', 'npm', 'i', 'x']), 'npm i x');
  assert.equal(argvCommand(['cmd', '/c', 'npm i x']), 'npm i x');
  assert.equal(argvCommand(['npm', 'i', 'a b']), "npm i 'a b'");
  assert.equal(shellCommandOf({ command: ['bash', '-lc', 'docker run nginx'] }), 'docker run nginx');
  assert.equal(shellCommandOf({ command: 'npx', args: ['-y', 'x'] }), 'npx -y x');
});

test('installs, pulls, IaC, models and extensions pre-classify to their subject types', () => {
  const t = (c) => [...commandSubjectTypes(c)];
  assert.ok(t('npm install left-pad').includes('package'));
  assert.ok(t('pip install requests').includes('package'));
  assert.ok(t('docker run --privileged nginx').includes('container'));
  assert.ok(t('docker pull nginx:latest').includes('image'));
  assert.ok(t('helm install x ./chart').includes('iac-module'));
  assert.ok(t('terraform init').includes('iac-module'));
  assert.ok(t('ollama pull llama3').includes('model'));
  assert.ok(t('code --install-extension ms-python.python').includes('extension'));
  assert.ok(t('curl https://x.sh | sh').includes('remote-script'));
  assert.equal(t('npm test').length, 0);
  assert.equal(t('ls -la').length, 0);
  assert.ok(pathSubjectTypes('Dockerfile').has('image'));
  assert.ok(pathSubjectTypes('.github/workflows/ci.yml').has('ci-workflow'));
  assert.ok(pathSubjectTypes('app/package.json').has('package'));
  assert.ok(pathSubjectTypes('.env.local').has('secret-file'));
  assert.equal(pathSubjectTypes('src/index.ts').size, 0);
});

test('escalation: the org set decides, an UNKNOWN set escalates every subject-bearing call', () => {
  const install = { command: 'npm install left-pad' };
  assert.equal(guardNeedsServer('Bash', install, false, { subjectTypes: ['package'] }), true);
  assert.equal(guardNeedsServer('Bash', install, false, { subjectTypes: ['image'] }), true, 'no package rule - the server still checks the package itself');
  assert.equal(guardNeedsServer('Bash', install, false, { subjectTypes: null }), true, 'unknown -> escalate');
  assert.equal(guardNeedsServer('Bash', install, false), true, 'an older call site with no set -> escalate');
  assert.equal(guardNeedsServer('Bash', { command: 'npm test' }, false, { subjectTypes: null }), false, 'nothing subject-bearing stays local');
  assert.equal(guardNeedsServer('PowerShell', { command: 'docker run nginx' }, false, { subjectTypes: ['container'] }), true);
  assert.equal(guardNeedsServer('local_shell', { command: ['bash', '-lc', 'pip install x'] }, false, { subjectTypes: ['package'] }), true);
  assert.equal(guardNeedsServer('Edit', { file_path: 'Dockerfile', old_string: 'USER node', new_string: '' }, false, { subjectTypes: ['container'] }), true);
  assert.equal(guardNeedsServer('Write', { file_path: 'src/a.ts', content: 'x' }, false, { subjectTypes: null }), false);
  assert.equal(guardNeedsServer('Bash', { command: 'cat > Dockerfile <<EOF\nFROM node\nEOF' }, false, { subjectTypes: ['image'] }), true, 'a heredoc Dockerfile');
  assert.ok(callSubjectTypes('apply_patch', { patch: '*** Begin Patch\n*** Add File: compose.yaml\n+services: {}\n*** End Patch' }).has('container'));
  assert.equal(subjectEscalation(new Set(), null), false);
});

test('an install reaches the server whatever the org rules say, because the server checks the package itself', () => {
  for (const command of ['npm install left-pad', 'pip install requests', 'npx -y some-cli', 'docker pull nginx:latest', 'terraform init', 'ollama pull llama3', 'code --install-extension ms-python.python', 'brew tap someone/formulae']) {
    assert.equal(guardNeedsServer('Bash', { command }, false, { subjectTypes: [] }), true, command);
  }
  assert.equal(guardNeedsServer('Edit', { file_path: 'package.json', old_string: '"a": "1"', new_string: '"a": "1", "b": "2"' }, false, { subjectTypes: [] }), true, 'a dependency added to a manifest');
  assert.equal(guardNeedsServer('Write', { file_path: '.env.local', content: 'A=1' }, false, { subjectTypes: ['image'] }), false, 'a type the server does not check itself still waits for an org rule');
  assert.equal(guardNeedsServer('Write', { file_path: '.env.local', content: 'A=1' }, false, { subjectTypes: ['secret-file'] }), true);
  assert.equal(guardNeedsServer('Bash', { command: 'gh workflow run ci.yml' }, false, { subjectTypes: [] }), false);
  assert.equal(guardNeedsServer('Bash', { command: 'npm test' }, false, { subjectTypes: [] }), false, 'running the tests installs nothing');
  assert.ok(serverScreened(commandSubjectTypes('pip install requests')));
  assert.equal(serverScreened(commandSubjectTypes('ls -la')), false);
  assert.equal(serverScreened(null), false);
});

test('the learned type set round-trips, expires, and is cleared by an answer without one', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-st-'));
  const file = path.join(dir, 'types.json');
  rememberSubjectTypes(['package', 'image'], { file, url: 'u' });
  assert.deepEqual(readSubjectTypes({ file, url: 'u' }), ['package', 'image']);
  assert.equal(readSubjectTypes({ file, url: 'other' }), null, 'another server’s set is not this one');
  assert.equal(readSubjectTypes({ file, url: 'u', now: Date.now() + 86_400_000 }), null, 'stale = unknown');
  rememberSubjectTypes(undefined, { file, url: 'u' });
  assert.equal(readSubjectTypes({ file, url: 'u' }), null, 'an older server clears it');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('post-edit reconstruction: an Edit of a governed file is sent WHOLE', () => {
  const r = read({ '/p/Dockerfile': 'FROM node:20\nUSER node\nCMD x\n', '/p/package.json': '{\n  "dependencies": {\n  }\n}\n' });
  const [d] = postEditContents('Edit', { file_path: 'Dockerfile', old_string: 'USER node\n', new_string: '' }, { cwd: '/p', read: r });
  assert.equal(d.path, 'Dockerfile');
  assert.equal(d.content, 'FROM node:20\nCMD x\n');
  const [pk] = postEditContents('Edit', { file_path: 'package.json', old_string: '"dependencies": {', new_string: '"dependencies": {\n    "left-pad": "^1.0.0",' }, { cwd: '/p', read: r });
  assert.match(pk.content, /"left-pad"/);
  assert.match(pk.content, /^\{/);
  assert.deepEqual(postEditContents('Edit', { file_path: 'Dockerfile', old_string: 'NOPE', new_string: 'x' }, { cwd: '/p', read: r }), [], 'an edit that does not apply sends nothing');
  assert.deepEqual(postEditContents('Write', { file_path: 'Dockerfile', content: 'FROM x' }, { cwd: '/p', read: r }), [], 'a whole-file write is not re-sent');
  const [mcp] = postEditContents('mcp__filesystem__edit_file', { path: 'Dockerfile', edits: [{ oldText: 'CMD x', newText: 'CMD y' }] }, { cwd: '/p', read: r });
  assert.match(mcp.content, /CMD y/);
});

test('apply_patch: Add File is the file, Update File is rebuilt against disk, argv shape too', () => {
  const r = read({ '/p/Dockerfile': 'FROM node:20\nUSER node\n' });
  const patch = '*** Begin Patch\n*** Update File: Dockerfile\n@@\n FROM node:20\n-USER node\n*** Add File: compose.yaml\n+services:\n+  web:\n+    image: nginx\n*** End Patch';
  const out = postEditContents('apply_patch', { input: patch }, { cwd: '/p', read: r });
  assert.deepEqual(out.map((o) => o.path), ['Dockerfile', 'compose.yaml']);
  assert.equal(out[0].content, 'FROM node:20\n');
  assert.match(out[1].content, /image: nginx/);
  const viaShell = postEditContents('shell', { command: ['apply_patch', patch] }, { cwd: '/p', read: r });
  assert.equal(viaShell.length, 2);
  const bad = '*** Begin Patch\n*** Update File: Dockerfile\n@@\n-NOT THERE\n+x\n*** End Patch';
  assert.deepEqual(postEditContents('apply_patch', { patch: bad }, { cwd: '/p', read: r }), [], 'a hunk that does not match sends nothing');
});

test('post_content is only built for governed paths, and never throws', () => {
  const r = read({ '/p/src/a.ts': 'const a = 1;\n', '/p/Dockerfile': 'FROM a\n' });
  assert.deepEqual(postContentField('Edit', { file_path: 'src/a.ts', old_string: '1', new_string: '2' }, { cwd: '/p' }, r), {});
  assert.equal(postContentField('Edit', { file_path: 'Dockerfile', old_string: 'a', new_string: 'b' }, { cwd: '/p' }, r).post_content[0].content, 'FROM b\n');
  assert.deepEqual(postContentField('Edit', { file_path: 'Dockerfile', old_string: 'a', new_string: 'b' }, { cwd: '/p' }, () => { throw new Error('boom'); }), {});
});

test('Copilot toolArgs arriving as a JSON string are parsed', () => {
  const n = normalizeGuardInput('copilot', { toolName: 'bash', toolArgs: '{"command":"npm i x"}' });
  assert.equal(n.tool_input.command, 'npm i x');
  const raw = normalizeGuardInput('copilot', { toolName: 'bash', toolArgs: 'not json' });
  assert.deepEqual(raw.tool_input, { raw: 'not json' });
});

