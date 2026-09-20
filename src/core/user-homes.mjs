import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const EXCLUDED_HOMES = {
  darwin: ['shared', 'guest', '.localized'],
  linux: ['lost+found'],
  win32: ['public', 'default', 'default user', 'all users', 'defaultuser0'],
};

function realIo() {
  return {
    readdir: (dir) => fs.readdirSync(dir),
    stat: (p) => fs.statSync(p),
    readFile: (p) => fs.readFileSync(p, 'utf8'),
  };
}

const safe = (fn, fallback = null) => {
  try {
    return fn();
  } catch {
    return fallback;
  }
};

function pathFor(platform) {
  return platform === 'win32' ? path.win32 : path.posix;
}

export function homesRoot(platform = process.platform, env = process.env) {
  if (platform === 'darwin') return '/Users';
  if (platform === 'win32') return path.win32.join(`${String(env.SystemDrive || env.SYSTEMDRIVE || 'C:').replace(/[\\/]+$/, '')}\\`, 'Users');
  return '/home';
}

export function listUserHomes({ platform = process.platform, env = process.env, io = realIo(), invokingHome = os.homedir() } = {}) {
  const p = pathFor(platform);
  const root = homesRoot(platform, env);
  const excluded = new Set(EXCLUDED_HOMES[platform] ?? EXCLUDED_HOMES.linux);
  const homes = [];
  for (const name of safe(() => io.readdir(root), []) ?? []) {
    if (!name || name.startsWith('.') || excluded.has(name.toLowerCase())) continue;
    const home = p.join(root, name);
    const st = safe(() => io.stat(home));
    if (!st || !st.isDirectory()) continue;
    homes.push({ home, user: name });
  }
  const same = (a, b) => (platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b);
  if (invokingHome && !homes.some((h) => same(h.home, invokingHome))) homes.push({ home: invokingHome, user: p.basename(invokingHome) || invokingHome });
  return homes.map((h) => ({ ...h, invoking: !!invokingHome && same(h.home, invokingHome) }));
}

function passwdNames(text) {
  const out = new Map();
  for (const line of String(text ?? '').split(/\r?\n/)) {
    const f = line.split(':');
    if (f.length >= 3 && /^\d+$/.test(f[2]) && !out.has(Number(f[2]))) out.set(Number(f[2]), f[0]);
  }
  return out;
}

function newestHome(homes, io) {
  let best = null;
  for (const h of homes) {
    const st = safe(() => io.stat(h.home));
    if (st && (!best || st.mtimeMs > best.st.mtimeMs)) best = { h, st };
  }
  return best;
}

export function consoleUser({ platform = process.platform, env = process.env, io = realIo(), homes = null } = {}) {
  const list = (homes ?? listUserHomes({ platform, env, io, invokingHome: null })).filter((h) => !h.invoking);
  if (platform === 'darwin') {
    const uid = safe(() => io.stat('/dev/console').uid);
    if (uid == null || uid === 0) return null;
    const hit = list.find((h) => safe(() => io.stat(h.home).uid) === uid);
    return hit ? hit.user : null;
  }
  if (platform === 'win32') {
    const name = String(env.USERNAME ?? '').trim();
    if (name && !name.endsWith('$')) return name;
    return newestHome(list, io)?.h.user ?? null;
  }
  const best = newestHome(list, io);
  if (!best) return null;
  const names = passwdNames(safe(() => io.readFile('/etc/passwd'), ''));
  return names.get(best.st.uid) ?? best.h.user;
}

export function orderHomes(homes, primary) {
  if (!primary) return homes.slice();
  const lower = String(primary).toLowerCase();
  return [...homes.filter((h) => h.user.toLowerCase() === lower), ...homes.filter((h) => h.user.toLowerCase() !== lower)];
}

function windowsSystem32(env) {
  return path.win32.join(env.SystemRoot || env.SYSTEMROOT || 'C:\\Windows', 'System32');
}

export function isSystemAccount({ platform = process.platform, env = process.env, getuid = process.getuid } = {}) {
  if (platform === 'win32') return String(env.USERNAME ?? '').endsWith('$');
  return typeof getuid === 'function' && getuid() === 0;
}

export function isPrivileged({ platform = process.platform, env = process.env, getuid = process.getuid, run = execFileSync } = {}) {
  if (platform !== 'win32') return typeof getuid === 'function' && getuid() === 0;
  if (String(env.USERNAME ?? '').endsWith('$')) return true;
  const out = safe(() => String(run(path.win32.join(windowsSystem32(env), 'whoami.exe'), ['/groups'], { encoding: 'utf8', timeout: 5000, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] })), '');
  return /S-1-16-(?:12288|16384)\b/.test(out);
}

export function reportUsername(opts = {}) {
  const current = safe(() => os.userInfo().username, '') || String((opts.env ?? process.env).USERNAME ?? '');
  if (!isSystemAccount(opts)) return current;
  return consoleUser(opts) ?? current;
}
