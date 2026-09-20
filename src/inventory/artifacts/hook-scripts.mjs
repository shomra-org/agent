import crypto from 'node:crypto';
import path from 'node:path';
import { loadConfig } from '../../core/config.mjs';
import { redactLocally } from '../../detect/local-redact.mjs';
import { readText } from './file-read.mjs';
import { MAX_BUNDLED } from './limits.mjs';
import { userDirs } from '../discovery/platform.mjs';

export const HOOK_SCRIPT_MODES = ['full', 'hash', 'off'];

const SCRIPT_EXT = /\.(?:sh|bash|zsh|ps1|psm1|bat|cmd|py|js|mjs|cjs|ts|rb|pl|php|lua)$/i;
const SECRET_PATH = /(?:^|[\\/])(?:\.env|\.ssh|\.aws|\.gnupg|\.netrc|\.npmrc|\.kube|\.docker)(?:[\\/]|$)|id_(?:rsa|dsa|ecdsa|ed25519)|secret|credential|password|\.pem$|\.key$/i;
const COMMAND_KEYS = new Set(['command', 'bash', 'sh', 'powershell', 'pwsh', 'windows', 'linux', 'osx']);
const EXTS = 'sh|bash|zsh|ps1|psm1|bat|cmd|py|js|mjs|cjs|ts|rb|pl|php|lua';
const REF_RE = new RegExp(`(?:^|["'\\s=;&|(\`])((?:\\$\\{?[A-Za-z_]\\w*\\}?|%[A-Za-z_]\\w*%|~|[A-Za-z]:)?[\\\\/]?(?:[\\w.@-]+[\\\\/])*[\\w.@-]+\\.(?:${EXTS}))(?=["'\\s;|&)\`]|$)`, 'g');
const QUOTED_REF_RE = new RegExp(`(["'])((?:\\$\\{?[A-Za-z_]\\w*\\}?|%[A-Za-z_]\\w*%|~|[A-Za-z]:)?[^"'\\n]*[\\\\/][^"'\\n]*?\\.(?:${EXTS}))\\1`, 'g');
const SHOMRA_GUARD_RE = /(?:^|[\\/])(?:shomra(?:-agent)?\.m?js|@shomra[\\/]agent[\\/].*)$/i;
const MAX_REFS = 40;

export function hookScriptMode(env = process.env, cfg = null) {
  const raw = String(env.SHOMRA_HOOK_SCRIPTS ?? (cfg ?? safeConfig()).hookScripts ?? 'full').trim().toLowerCase();
  return HOOK_SCRIPT_MODES.includes(raw) ? raw : 'full';
}

function safeConfig() {
  try {
    return loadConfig();
  } catch {
    return {};
  }
}

export function hookCommands(canonical) {
  let doc;
  try {
    doc = JSON.parse(canonical);
  } catch {
    return [];
  }
  const out = [];
  const walk = (n, depth) => {
    if (!n || depth > 12 || out.length > 200) return;
    if (Array.isArray(n)) return n.forEach((v) => walk(v, depth + 1));
    if (typeof n !== 'object') return;
    for (const [k, v] of Object.entries(n)) {
      if (COMMAND_KEYS.has(k) && typeof v === 'string') out.push(v);
      else walk(v, depth + 1);
    }
  };
  walk(doc?.hooks, 0);
  return out;
}

export function scriptRefs(command) {
  const out = new Set();
  const cmd = String(command).replace(/(["'])(\$\{?[A-Za-z_]\w*\}?|%[A-Za-z_]\w*%)\1(?=[\\/])/g, '$2');
  for (const m of cmd.matchAll(QUOTED_REF_RE)) if (out.size < MAX_REFS) out.add(m[2].trim());
  const unquoted = cmd.replace(QUOTED_REF_RE, ' ');
  for (const m of unquoted.matchAll(REF_RE)) {
    if (out.size >= MAX_REFS) break;
    out.add(m[1].trim());
  }
  return [...out];
}

export function pluginRootOf(hookFile) {
  const norm = hookFile.replace(/\\/g, '/');
  if (/\/hooks\/hooks\.json$/i.test(norm)) return path.dirname(path.dirname(hookFile));
  if (/\/\.claude-plugin\/plugin\.json$/i.test(norm)) return path.dirname(path.dirname(hookFile));
  return path.dirname(hookFile);
}

export function resolveRef(ref, { hookFile, projectDir, home }) {
  const m = /^(\$\{?([A-Za-z_]\w*)\}?|%([A-Za-z_]\w*)%|~)([\\/].*)$/.exec(ref);
  if (m) {
    const name = (m[2] ?? m[3] ?? '').toUpperCase();
    const rest = m[4].replace(/^[\\/]/, '');
    const base =
      m[1] === '~' || name === 'HOME' || name === 'USERPROFILE' ? userDirs(home).HOME
        : name === 'CLAUDE_PLUGIN_ROOT' || name === 'EXTENSIONPATH' ? pluginRootOf(hookFile)
          : /^(?:CLAUDE|GEMINI|CURSOR|QWEN)_PROJECT_DIR$|^PWD$/.test(name) ? projectDir
            : null;
    return base ? [path.join(base, rest)] : [];
  }
  if (path.isAbsolute(ref) || /^[A-Za-z]:[\\/]/.test(ref)) return [ref];
  return [...new Set([path.resolve(projectDir, ref), path.resolve(path.dirname(hookFile), ref)])];
}

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

export function bundleHookScripts(artifact, hookFile, { projectDir, relPath, budget, capped, mode = hookScriptMode(), home }) {
  if (mode === 'off') return;
  const refs = [...new Set(hookCommands(artifact.content).flatMap(scriptRefs))].filter((r) => SCRIPT_EXT.test(r));
  const scripts = [];
  for (const ref of refs) {
    if (SECRET_PATH.test(ref)) continue;
    if (SHOMRA_GUARD_RE.test(ref)) {
      scripts.push({ ref, state: 'shomra-guard' });
      continue;
    }
    if (artifact.files.length >= MAX_BUNDLED) {
      capped.push({ reason: 'bundle-cap', path: artifact.path });
      break;
    }
    const target = resolveRef(ref, { hookFile, projectDir, home }).find((p) => readText(p) != null);
    if (!target || SECRET_PATH.test(target)) {
      scripts.push({ ref, state: 'missing' });
      continue;
    }
    const read = readText(target);
    const digest = sha256(read.text);
    const wirePath = relPath(target) ?? ref.replace(/^(?:\$\{?\w+\}?|%\w+%|~)?[\\/]*/, '').replace(/\\/g, '/');
    if (mode === 'hash') {
      artifact.files.push({ path: wirePath, content: null, binary: false, sha256: digest, withheld: true });
      scripts.push({ ref, path: wirePath, sha256: digest, bytes: read.bytes, state: 'withheld' });
      continue;
    }
    if (read.bytes > budget.bytes) {
      capped.push({ reason: 'byte-budget', path: wirePath });
      scripts.push({ ref, path: wirePath, sha256: digest, bytes: read.bytes, state: 'over-budget' });
      continue;
    }
    const masked = redactLocally(read.text, { categories: ['secret'] });
    budget.bytes -= Buffer.byteLength(masked.text);
    artifact.files.push({ path: wirePath, content: masked.text, binary: false, sha256: digest, ...(read.truncated ? { truncated: true } : {}) });
    scripts.push({ ref, path: wirePath, sha256: digest, bytes: read.bytes, state: 'sent', maskedSecrets: masked.masked.length });
  }
  if (refs.length) artifact.metadata.hookScripts = { mode, scripts: scripts.slice(0, MAX_BUNDLED) };
}
