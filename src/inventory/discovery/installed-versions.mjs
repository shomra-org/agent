import fs from 'node:fs';
import path from 'node:path';
import { userDirs } from './platform.mjs';

export const NPM_AGENT_PACKAGES = {
  'claude-code': '@anthropic-ai/claude-code',
  codex: '@openai/codex',
  gemini: '@google/gemini-cli',
};

export const OLLAMA_PACKAGE = { ecosystem: 'go', name: 'github.com/ollama/ollama' };

const VERSION_RE = /^\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.+-]+)?$/;
const MAX_MANIFEST_BYTES = 512 * 1024;
const MAX_LOG_TAIL = 1024 * 1024;

export function cleanVersion(raw) {
  if (typeof raw !== 'string') return null;
  const v = raw.trim().replace(/^v(?=\d)/, '');
  return v.length <= 64 && VERSION_RE.test(v) ? v : null;
}

export function parsePackageVersion(text, expectedName) {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    return null;
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return null;
  if (expectedName && doc.name !== expectedName) return null;
  return cleanVersion(doc.version);
}

export function parsePlistVersion(xml) {
  if (typeof xml !== 'string') return null;
  const m = /<key>\s*CFBundleShortVersionString\s*<\/key>\s*<string>\s*([^<]*?)\s*<\/string>/.exec(xml);
  return m ? cleanVersion(m[1]) : null;
}

export function parseOllamaLogVersion(text) {
  if (typeof text !== 'string') return null;
  let last = null;
  for (const m of text.matchAll(/(?:^|[\s,{])version=(?:"([^"\s]*)"|([^\s",}]+))/g)) {
    const v = cleanVersion(m[1] ?? m[2]);
    if (v) last = v;
  }
  return last;
}

function defaultIo() {
  return {
    platform: process.platform,
    readFile: (file, max) => {
      const st = fs.statSync(file);
      if (!st.isFile() || st.size > max) return null;
      return fs.readFileSync(file, 'utf8');
    },
    readTail: (file, max) => {
      const st = fs.statSync(file);
      if (!st.isFile()) return null;
      const len = Math.min(st.size, max);
      const fd = fs.openSync(file, 'r');
      try {
        const buf = Buffer.alloc(len);
        fs.readSync(fd, buf, 0, len, st.size - len);
        return buf.toString('utf8');
      } finally {
        fs.closeSync(fd);
      }
    },
    readdir: (dir) => fs.readdirSync(dir),
  };
}

const tryRead = (fn) => {
  try {
    return fn();
  } catch {
    return null;
  }
};

export function npmGlobalRoots(home, io = defaultIo()) {
  const { HOME, APPDATA } = userDirs(home);
  const roots = [];
  if (io.platform === 'win32') roots.push(path.join(APPDATA, 'npm', 'node_modules'), path.join(HOME, 'AppData', 'Roaming', 'npm', 'node_modules'));
  roots.push(path.join(HOME, '.npm-global', 'lib', 'node_modules'));
  if (io.platform !== 'win32') roots.push('/usr/local/lib/node_modules', '/opt/homebrew/lib/node_modules');
  roots.push(path.join(HOME, '.claude', 'local', 'node_modules'));
  const nvm = path.join(HOME, '.nvm', 'versions', 'node');
  for (const v of (tryRead(() => io.readdir(nvm)) ?? []).slice(0, 50)) roots.push(path.join(nvm, v, 'lib', 'node_modules'));
  return [...new Set(roots)];
}

export function npmInstalledVersions(pkgName, roots, io = defaultIo()) {
  const found = new Set();
  for (const root of roots) {
    const text = tryRead(() => io.readFile(path.join(root, ...pkgName.split('/'), 'package.json'), MAX_MANIFEST_BYTES));
    const v = text == null ? null : parsePackageVersion(text, pkgName);
    if (v) found.add(v);
  }
  return [...found];
}

export function agentVersionMeta(vendor, home, io = defaultIo()) {
  const name = NPM_AGENT_PACKAGES[vendor];
  if (!name) return {};
  const versions = npmInstalledVersions(name, npmGlobalRoots(home, io), io);
  return versionMeta({ ecosystem: 'npm', name }, versions);
}

export function ollamaVersionMeta(home, io = defaultIo()) {
  const { HOME, LOCALAPPDATA } = userDirs(home);
  let v = null;
  if (io.platform === 'darwin') v = parsePlistVersion(tryRead(() => io.readFile('/Applications/Ollama.app/Contents/Info.plist', MAX_MANIFEST_BYTES)));
  if (!v) {
    const log = io.platform === 'win32' ? path.join(LOCALAPPDATA, 'Ollama', 'server.log') : path.join(HOME, '.ollama', 'logs', 'server.log');
    v = parseOllamaLogVersion(tryRead(() => io.readTail(log, MAX_LOG_TAIL)));
  }
  return versionMeta(OLLAMA_PACKAGE, v ? [v] : []);
}

function versionMeta(pkg, versions) {
  const out = { package: { ...pkg } };
  if (versions.length === 1) out.version = versions[0];
  else if (versions.length > 1) out.installedVersions = versions.slice(0, 10);
  return out;
}
