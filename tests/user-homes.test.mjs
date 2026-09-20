import test from 'node:test';
import assert from 'node:assert/strict';
import { consoleUser, homesRoot, isSystemAccount, listUserHomes, orderHomes, reportUsername } from '../src/core/user-homes.mjs';
import { mergeHomeArtifacts, mergeHomeAssets } from '../src/inventory/multi-home.mjs';
import { userDirs } from '../src/inventory/discovery/platform.mjs';

function fakeIo(tree, files = {}) {
  const key = (p) => p.toLowerCase();
  const nodes = new Map(Object.entries(tree).map(([p, v]) => [key(p), v]));
  return {
    readdir: (dir) => {
      const n = nodes.get(key(dir));
      if (!n?.children) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      return n.children;
    },
    stat: (p) => {
      const n = nodes.get(key(p));
      if (!n) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      return { isDirectory: () => n.dir !== false, uid: n.uid ?? 0, mtimeMs: n.mtimeMs ?? 0 };
    },
    readFile: (p) => {
      if (!(p in files)) throw new Error('ENOENT');
      return files[p];
    },
  };
}

test('macOS homes skip Shared, Guest and .localized and add the invoking root home', () => {
  const io = fakeIo({
    '/Users': { children: ['alice', 'Shared', 'Guest', '.localized', 'bob', 'notes.txt'] },
    '/Users/alice': { uid: 501 },
    '/Users/bob': { uid: 502 },
    '/Users/Shared': {},
    '/Users/Guest': {},
    '/Users/notes.txt': { dir: false },
  });
  const homes = listUserHomes({ platform: 'darwin', env: {}, io, invokingHome: '/var/root' });
  assert.deepEqual(homes.map((h) => h.user), ['alice', 'bob', 'root']);
  assert.deepEqual(homes.filter((h) => h.invoking).map((h) => h.home), ['/var/root']);
});

test('Windows homes come from SystemDrive and skip the built-in profiles', () => {
  assert.equal(homesRoot('win32', { SystemDrive: 'D:' }), 'D:\\Users');
  const io = fakeIo({
    'D:\\Users': { children: ['Public', 'Default', 'Default User', 'All Users', 'defaultuser0', 'dana', 'eli', 'desktop.ini'] },
    'D:\\Users\\dana': { mtimeMs: 10 },
    'D:\\Users\\eli': { mtimeMs: 20 },
    'D:\\Users\\Public': {},
    'D:\\Users\\Default': {},
    'D:\\Users\\defaultuser0': {},
    'D:\\Users\\desktop.ini': { dir: false },
  });
  const homes = listUserHomes({ platform: 'win32', env: { SystemDrive: 'D:' }, io, invokingHome: 'D:\\Windows\\system32\\config\\systemprofile' });
  assert.deepEqual(homes.map((h) => h.user), ['dana', 'eli', 'systemprofile']);
});

test('Linux lists /home and includes /root only as the invoking home', () => {
  const io = fakeIo({ '/home': { children: ['lost+found', 'kim', 'lee'] }, '/home/kim': {}, '/home/lee': {}, '/home/lost+found': {} });
  assert.deepEqual(listUserHomes({ platform: 'linux', env: {}, io, invokingHome: '/root' }).map((h) => h.home), ['/home/kim', '/home/lee', '/root']);
  const asKim = listUserHomes({ platform: 'linux', env: {}, io, invokingHome: '/home/kim' });
  assert.deepEqual(asKim.map((h) => h.home), ['/home/kim', '/home/lee']);
  assert.equal(asKim[0].invoking, true);
});

test('macOS console user is resolved from the /dev/console owner uid', () => {
  const tree = { '/Users': { children: ['alice', 'bob'] }, '/Users/alice': { uid: 501 }, '/Users/bob': { uid: 502 }, '/dev/console': { uid: 502, dir: false } };
  assert.equal(consoleUser({ platform: 'darwin', env: {}, io: fakeIo(tree) }), 'bob');
  assert.equal(consoleUser({ platform: 'darwin', env: {}, io: fakeIo({ ...tree, '/dev/console': { uid: 0, dir: false } }) }), null);
});

test('Windows console user is USERNAME unless SYSTEM, then the most recently used home', () => {
  const io = fakeIo({ 'C:\\Users': { children: ['dana', 'eli'] }, 'C:\\Users\\dana': { mtimeMs: 50 }, 'C:\\Users\\eli': { mtimeMs: 20 } });
  assert.equal(consoleUser({ platform: 'win32', env: { USERNAME: 'eli' }, io }), 'eli');
  assert.equal(consoleUser({ platform: 'win32', env: { USERNAME: 'HOST$' }, io }), 'dana');
  assert.equal(isSystemAccount({ platform: 'win32', env: { USERNAME: 'HOST$' } }), true);
  assert.equal(reportUsername({ platform: 'win32', env: { USERNAME: 'HOST$' }, io }), 'dana');
});

test('Linux console user is the owner of the newest home, named through /etc/passwd', () => {
  const io = fakeIo(
    { '/home': { children: ['kim', 'lee'] }, '/home/kim': { uid: 1000, mtimeMs: 5 }, '/home/lee': { uid: 1001, mtimeMs: 9 } },
    { '/etc/passwd': 'root:x:0:0::/root:/bin/bash\nlee-real:x:1001:1001::/home/lee:/bin/bash\n' },
  );
  assert.equal(consoleUser({ platform: 'linux', env: {}, io }), 'lee-real');
});

test('the console user is discovered first', () => {
  const homes = [{ home: '/Users/a', user: 'a' }, { home: '/Users/b', user: 'b' }];
  assert.deepEqual(orderHomes(homes, 'B').map((h) => h.user), ['b', 'a']);
  assert.deepEqual(orderHomes(homes, null).map((h) => h.user), ['a', 'b']);
});

test('merged assets carry osUser and identical identifiers from two homes do not collapse', () => {
  const agent = { type: 'AI_AGENT', name: 'Claude Code', identifier: 'agent:claude-code', metadata: { detectedAt: 'x' } };
  const runs = [
    { home: '/Users/alice', user: 'alice', invoking: false, assets: [agent, agent] },
    { home: '/Users/bob', user: 'bob', invoking: false, assets: [agent] },
    { home: '/var/root', user: 'root', invoking: true, assets: [{ type: 'MODEL_KEY', name: 'OPENAI_API_KEY', identifier: 'env:OPENAI_API_KEY', metadata: {} }] },
  ];
  const merged = mergeHomeAssets(runs);
  assert.equal(merged.length, 3);
  assert.deepEqual(merged.map((a) => a.identifier), ['agent:claude-code', 'agent:claude-code@bob', 'env:OPENAI_API_KEY']);
  assert.deepEqual(merged.map((a) => a.metadata.osUser), ['alice', 'bob', undefined]);
  assert.equal(agent.metadata.osUser, undefined);
});

test('merged artifacts are tagged per account and marketplace counts add up', () => {
  const art = { kind: 'skill', path: '.claude/skills/x/SKILL.md', metadata: {} };
  const out = mergeHomeArtifacts([
    { home: '/Users/a', user: 'a', invoking: false, artifacts: [art], capped: [{ reason: 'byte-budget' }], available: [{ marketplace: 'm', count: 2 }] },
    { home: '/Users/b', user: 'b', invoking: false, artifacts: [art], capped: [], available: [{ marketplace: 'm', count: 3 }] },
  ]);
  assert.deepEqual(out.artifacts.map((a) => a.metadata.osUser), ['a', 'b']);
  assert.equal(out.capped[0].osUser, 'a');
  assert.deepEqual(out.available, [{ marketplace: 'm', count: 5 }]);
});

test('userDirs derives AppData from an explicit home, not from the invoking account', () => {
  const other = process.platform === 'win32' ? 'Z:\\Users\\other' : '/nonexistent/other';
  const d = userDirs(other);
  assert.equal(d.own, false);
  assert.equal(d.HOME, other);
  assert.ok(d.APPDATA.startsWith(other));
  assert.ok(d.LOCALAPPDATA.startsWith(other));
  assert.ok(d.vscodeUserDir('Code').startsWith(other));
  assert.equal(userDirs().own, true);
});
