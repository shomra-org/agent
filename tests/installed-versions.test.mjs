import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {
  agentVersionMeta, cleanVersion, npmGlobalRoots, npmInstalledVersions, ollamaVersionMeta, parseOllamaLogVersion, parsePackageVersion, parsePlistVersion,
} from '../src/inventory/discovery/installed-versions.mjs';

const HOME = process.platform === 'win32' ? 'Z:\\Users\\dana' : '/nonexistent/home/dana';

function io(platform, files = {}, dirs = {}) {
  return {
    platform,
    readFile: (f) => {
      if (!(f in files)) throw new Error('ENOENT');
      return files[f];
    },
    readTail: (f) => {
      if (!(f in files)) throw new Error('ENOENT');
      return files[f];
    },
    readdir: (d) => {
      if (!(d in dirs)) throw new Error('ENOENT');
      return dirs[d];
    },
  };
}

test('package.json version is read only for the expected package and a real version string', () => {
  assert.equal(parsePackageVersion('{"name":"@openai/codex","version":"0.46.0"}', '@openai/codex'), '0.46.0');
  assert.equal(parsePackageVersion('{"name":"@evil/codex","version":"0.46.0"}', '@openai/codex'), null);
  assert.equal(parsePackageVersion('{"name":"@openai/codex","version":"latest"}', '@openai/codex'), null);
  assert.equal(parsePackageVersion('not json', '@openai/codex'), null);
  assert.equal(cleanVersion('v1.2.3-beta.1'), '1.2.3-beta.1');
  assert.equal(cleanVersion('1'), null);
});

test('Info.plist CFBundleShortVersionString is parsed from XML text', () => {
  const plist = '<?xml version="1.0"?><plist><dict><key>CFBundleName</key><string>Ollama</string><key>CFBundleShortVersionString</key>\n  <string>0.12.3</string></dict></plist>';
  assert.equal(parsePlistVersion(plist), '0.12.3');
  assert.equal(parsePlistVersion('<plist><dict></dict></plist>'), null);
  assert.equal(parsePlistVersion(null), null);
});

test('Ollama server.log yields the LAST version= token', () => {
  const log = [
    'time=2025-01-01 level=INFO source=routes.go msg="Listening" version=0.5.1',
    'garbage line version=notaversion',
    'time=2025-02-01 level=INFO source=routes.go msg="Listening" version="0.6.2"',
    'time=2025-02-01 level=INFO msg="inference compute" library=cuda compute=8.6',
  ].join('\n');
  assert.equal(parseOllamaLogVersion(log), '0.6.2');
  assert.equal(parseOllamaLogVersion('no versions here'), null);
  assert.equal(parseOllamaLogVersion('xversion=1.2.3'), null);
});

test('global npm roots cover per-home, system, Claude local and nvm installs', () => {
  const nvm = path.join(HOME, '.nvm', 'versions', 'node');
  const roots = npmGlobalRoots(HOME, io('linux', {}, { [nvm]: ['v20.1.0', 'v22.3.0'] }));
  assert.ok(roots.includes(path.join(HOME, '.npm-global', 'lib', 'node_modules')));
  assert.ok(roots.includes('/usr/local/lib/node_modules'));
  assert.ok(roots.includes('/opt/homebrew/lib/node_modules'));
  assert.ok(roots.includes(path.join(HOME, '.claude', 'local', 'node_modules')));
  assert.ok(roots.includes(path.join(nvm, 'v22.3.0', 'lib', 'node_modules')));
  const win = npmGlobalRoots(HOME, io('win32'));
  assert.ok(win.includes(path.join(HOME, 'AppData', 'Roaming', 'npm', 'node_modules')));
  assert.ok(!win.includes('/usr/local/lib/node_modules'));
});

test('agent version is reported only when every install agrees', () => {
  const a = path.join(HOME, '.npm-global', 'lib', 'node_modules');
  const b = path.join(HOME, '.claude', 'local', 'node_modules');
  const pkg = (v) => JSON.stringify({ name: '@anthropic-ai/claude-code', version: v });
  const one = io('linux', { [path.join(a, '@anthropic-ai', 'claude-code', 'package.json')]: pkg('1.0.80') });
  assert.deepEqual(agentVersionMeta('claude-code', HOME, one), { package: { ecosystem: 'npm', name: '@anthropic-ai/claude-code' }, version: '1.0.80' });
  const two = io('linux', { [path.join(a, '@anthropic-ai', 'claude-code', 'package.json')]: pkg('1.0.80'), [path.join(b, '@anthropic-ai', 'claude-code', 'package.json')]: pkg('2.0.1') });
  const meta = agentVersionMeta('claude-code', HOME, two);
  assert.equal(meta.version, undefined);
  assert.deepEqual(meta.installedVersions.sort(), ['1.0.80', '2.0.1']);
  assert.deepEqual(agentVersionMeta('claude-code', HOME, io('linux')), { package: { ecosystem: 'npm', name: '@anthropic-ai/claude-code' } });
  assert.deepEqual(agentVersionMeta('cursor', HOME, io('linux')), {});
  assert.deepEqual(npmInstalledVersions('@google/gemini-cli', [a], io('linux')), []);
});

test('Ollama version prefers the macOS app bundle, else the server log', () => {
  const plist = '<dict><key>CFBundleShortVersionString</key><string>0.9.0</string></dict>';
  const mac = io('darwin', { '/Applications/Ollama.app/Contents/Info.plist': plist });
  assert.deepEqual(ollamaVersionMeta(HOME, mac), { package: { ecosystem: 'go', name: 'github.com/ollama/ollama' }, version: '0.9.0' });
  const linux = io('linux', { [path.join(HOME, '.ollama', 'logs', 'server.log')]: 'version=0.3.1\nversion=0.4.0\n' });
  assert.equal(ollamaVersionMeta(HOME, linux).version, '0.4.0');
  const win = io('win32', { [path.join(HOME, 'AppData', 'Local', 'Ollama', 'server.log')]: 'msg=x version=0.7.1' });
  assert.equal(ollamaVersionMeta(HOME, win).version, '0.7.1');
  assert.equal(ollamaVersionMeta(HOME, io('linux')).version, undefined);
});
