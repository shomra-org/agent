import { stripCommandPrefixes } from './fetch-exec.mjs';
import { targetsExternalNetwork } from './network.mjs';

export const EPHEMERAL_RM_TARGET_RE =
  /^(\.\/)?(node_modules|dist|build|out|coverage|\.nyc_output|target|\.next|\.nuxt|\.turbo|\.svelte-kit|\.cache|\.parcel-cache|__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.tox|venv|\.venv|\.eggs|[\w.-]+\.egg-info)\/?\*?$/i;

export const BENIGN_ABSOLUTE_RM_RE =
  /^\/(var\/(lib\/apt\/lists|cache|tmp|log)|tmp|usr\/share\/(doc|man|locale|info)|root\/\.cache|home\/[\w.-]+\/\.cache|opt\/[\w.-]+\/\.cache)(\/|$|\*)/i;

export const CATASTROPHIC_RM_TARGET_RE = /^(\/|~|\$|\$\{|%\w+%|[A-Za-z]:[\\/]|\.\.?$|\.\.\/|\*$)/;

const EXTRA_EPHEMERAL_DIR_RE =
  /^(?:\.\/)?(?:tmp|temp|\.tmp|\.gradle|\.dart_tool|\.angular|\.expo|\.output|\.vercel|\.docusaurus|storybook-static|\.coverage|htmlcov|\.hypothesis|\.serverless|\.webpack|\.vite|\.astro|\.nx)\/?\*?$/i;

const EPHEMERAL_FILE_RE = /^(?:\.\/)?(?:[\w.-]+\/)*[\w*.-]*\.(?:log|tmp|temp|bak|swp|orig|rej|pyc|pyo|o|obj|class|out|pid|tsbuildinfo)$/i;

const LOCKFILE_RE =
  /^(?:\.\/)?(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|Cargo\.lock|poetry\.lock|Pipfile\.lock|composer\.lock|Gemfile\.lock|uv\.lock|\.DS_Store|\.eslintcache)$/i;

export const HOME_CACHE_RE = /^~\/(?:\.cache|Library\/Caches)\//i;

const PACKAGE_MANAGERS = new Set([
  'git', 'npm', 'pnpm', 'yarn', 'bun', 'brew', 'cargo', 'conda', 'mamba', 'poetry', 'uv', 'pip', 'pip3', 'pipx',
  'gem', 'dotnet', 'flatpak', 'snap', 'volta', 'asdf', 'mise', 'rustup', 'go', 'deno', 'composer',
]);

const NETWORK_SENDERS = new Set(['curl', 'wget', 'nc', 'ncat', 'socat', 'http', 'https', 'xh']);

const SENSITIVE_FILE_RE =
  /(?:^|[\s'"=@/])(?:\.env(?:\.[\w-]+)?|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.pgpass|id_(?:rsa|dsa|ecdsa|ed25519)|credentials|kubeconfig)(?=$|[\s'"])|\.(?:aws|ssh|gnupg|kube)\//i;

export function disposableTarget(t) {
  return (
    EPHEMERAL_RM_TARGET_RE.test(t) ||
    BENIGN_ABSOLUTE_RM_RE.test(t) ||
    EXTRA_EPHEMERAL_DIR_RE.test(t) ||
    EPHEMERAL_FILE_RE.test(t) ||
    LOCKFILE_RE.test(t) ||
    HOME_CACHE_RE.test(t)
  );
}

export function shellWords(input) {
  const s = String(input ?? '');
  const out = [];
  let cur = '';
  let quote = null;
  let started = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (quote) {
      if (ch === quote) quote = null;
      else if (ch === '\\' && quote === '"' && i + 1 < s.length) cur += s[++i];
      else cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      started = true;
      continue;
    }
    if (ch === '\\' && i + 1 < s.length) {
      cur += s[++i];
      started = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (started) out.push(cur);
      cur = '';
      started = false;
      continue;
    }
    cur += ch;
    started = true;
  }
  if (started) out.push(cur);
  return out;
}

export function commandSegments(command) {
  const s = String(command ?? '');
  const out = [];
  let cur = '';
  let quote = null;
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (quote) {
      cur += ch;
      if (ch === quote) quote = null;
      else if (ch === '\\' && quote === '"' && i + 1 < s.length) cur += s[++i];
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === '$' && s[i + 1] === '(') {
      depth++;
      cur += '$(';
      i++;
      continue;
    }
    if (ch === ')' && depth > 0) {
      depth--;
      cur += ch;
      continue;
    }
    if (depth === 0 && (ch === ';' || ch === '\n' || ch === '|' || ch === '&')) {
      out.push(cur);
      cur = '';
      if ((ch === '|' || ch === '&') && s[i + 1] === ch) i++;
      continue;
    }
    cur += ch;
  }
  out.push(cur);
  return out.map((x) => x.trim()).filter(Boolean);
}

function rmDestroys(args) {
  const flags = [];
  const targets = [];
  let endOfFlags = false;
  for (const w of args) {
    if (!endOfFlags && w === '--') {
      endOfFlags = true;
      continue;
    }
    if (!endOfFlags && w.startsWith('-') && w !== '-') flags.push(w);
    else targets.push(w);
  }
  const recursive = flags.some((f) => /^-[a-zA-Z]*[rR]/.test(f) || f === '--recursive');
  if (!targets.length) return true;
  for (const t of targets) {
    if (disposableTarget(t)) continue;
    if (CATASTROPHIC_RM_TARGET_RE.test(t)) return true;
    if (/[*?]/.test(t)) return true;
    if (recursive) return true;
  }
  return false;
}

const hasShortFlag = (args, letter) => args.some((a) => new RegExp(`^-[a-zA-Z]*${letter}`).test(a));

function skipGlobalFlags(args, withValue) {
  let i = 0;
  while (i < args.length && args[i].startsWith('-')) {
    const flag = args[i].split('=')[0];
    i += withValue.has(flag) && !args[i].includes('=') ? 2 : 1;
  }
  return i;
}

const GIT_VALUE_FLAGS = new Set(['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--exec-path']);

function gitDestroys(args) {
  const i = skipGlobalFlags(args, GIT_VALUE_FLAGS);
  const sub = args[i];
  const rest = args.slice(i + 1);
  const wholeTree = rest.some((a) => a === '.' || a === ':/' || a === ':/.' || a === '*');
  if (sub === 'clean') {
    const force = hasShortFlag(rest, 'f') || rest.includes('--force');
    const dry = hasShortFlag(rest, 'n') || rest.includes('--dry-run') || hasShortFlag(rest, 'i') || rest.includes('--interactive');
    return force && !dry;
  }
  if (sub === 'reset') return rest.includes('--hard');
  if (sub === 'checkout') return rest.includes('-f') || rest.includes('--force') || wholeTree;
  if (sub === 'restore') {
    const onlyStaged = (rest.includes('--staged') || rest.includes('-S')) && !rest.includes('--worktree') && !rest.includes('-W');
    return wholeTree && !onlyStaged;
  }
  if (sub === 'stash') return rest[0] === 'clear';
  return false;
}

const COMPOSE_VALUE_FLAGS = new Set(['-f', '--file', '-p', '--project-name', '--profile', '--env-file', '--project-directory', '--ansi', '--parallel']);
const DOCKER_VALUE_FLAGS = new Set(['--context', '-c', '-H', '--host', '--config', '-l', '--log-level']);

function composeDownVolumes(args) {
  const i = skipGlobalFlags(args, COMPOSE_VALUE_FLAGS);
  const rest = args.slice(i + 1);
  return args[i] === 'down' && (hasShortFlag(rest, 'v') || rest.includes('--volumes'));
}

function dockerDestroys(args) {
  const i = skipGlobalFlags(args, DOCKER_VALUE_FLAGS);
  const sub = args[i];
  const rest = args.slice(i + 1);
  if (sub === 'compose') return composeDownVolumes(rest);
  if (sub === 'volume') return ['rm', 'remove', 'prune'].includes(rest[0]);
  if (sub === 'system') return rest[0] === 'prune' && rest.includes('--volumes');
  const removesContainer = sub === 'rm' || (sub === 'container' && ['rm', 'remove', 'prune'].includes(rest[0]));
  return removesContainer && (hasShortFlag(rest, 'v') || rest.includes('--volumes'));
}

function xargsDestroys(args) {
  const XARGS_VALUE_FLAGS = new Set(['-I', '-i', '-n', '-P', '-L', '-d', '-E', '-s', '-a']);
  const i = skipGlobalFlags(args, XARGS_VALUE_FLAGS);
  return (args[i] ?? '').replace(/^.*\//, '') === 'rm';
}

const RM_WORD_RE = /(?<![-\w])rm\b/i;
const OPAQUE_EXECUTABLE_RE = /^["']?(?:\$|`)/;

function segmentDestroys(segment, depth) {
  const stripped = stripCommandPrefixes(segment);
  if (OPAQUE_EXECUTABLE_RE.test(stripped)) return RM_WORD_RE.test(stripped);
  const words = shellWords(stripped);
  if (!words.length) return false;
  const cmd = words[0].replace(/^.*\//, '');
  const rest = words.slice(1);
  if (cmd === 'rm') return rmDestroys(rest);
  if (cmd === 'xargs') return xargsDestroys(rest);
  if (cmd === 'find') {
    return rest.includes('-delete') || rest.some((w, i) => ['-exec', '-execdir', '-ok'].includes(w) && /(?:^|\/)rm$/.test(rest[i + 1] ?? ''));
  }
  if (cmd === 'git') return gitDestroys(rest);
  if (cmd === 'docker' || cmd === 'podman' || cmd === 'nerdctl') return dockerDestroys(rest);
  if (cmd === 'docker-compose' || cmd === 'podman-compose') return composeDownVolumes(rest);
  if (/^(?:ba|z|k|da)?sh$/.test(cmd) && rest[0] === '-c' && rest[1] && depth < 3) return destructiveShell(rest[1], depth + 1);
  const sep = rest.indexOf('--');
  if (sep !== -1 && depth < 3 && rest.length > sep + 1) return segmentDestroys(rest.slice(sep + 1).join(' '), depth + 1);
  if (!PACKAGE_MANAGERS.has(cmd) && rest.includes('rm')) return true;
  return false;
}

export function destructiveShell(command, depth = 0) {
  return commandSegments(command).some((seg) => segmentDestroys(seg, depth));
}

const ENV_DUMP_ARG_RE = /\b(?:curl|wget)\b[^\n]{0,220}(?:\$\(\s*(?:env|printenv|set)\s*\)|`\s*(?:env|printenv|set)\s*`)/i;

function pipelineStages(line) {
  return String(line).split(/(?<!\|)\|(?!\|)/).map((s) => shellWords(stripCommandPrefixes(s)));
}

function readsSecrets(words) {
  const cmd = (words[0] ?? '').replace(/^.*\//, '');
  if (['env', 'printenv'].includes(cmd)) return words.slice(1).every((w) => w.startsWith('-'));
  if (cmd === 'set' && words.length === 1) return true;
  if (NETWORK_SENDERS.has(cmd)) return false;
  return words.slice(1).some(sensitiveFile);
}

const UPLOAD_FLAGS = new Set(['--post-file', '--body-file', '-T', '--upload-file']);

const sensitiveFile = (v) => !!v && !v.includes('://') && SENSITIVE_FILE_RE.test(` ${v} `);

function uploadsSecrets(words) {
  for (let k = 1; k < words.length; k++) {
    const w = words[k];
    const at = /(?:^|=)@(.+)$/.exec(w);
    if (at && sensitiveFile(at[1])) return true;
    const flag = w.split('=')[0];
    if (!UPLOAD_FLAGS.has(flag)) continue;
    const value = w.includes('=') ? w.slice(w.indexOf('=') + 1) : words[k + 1];
    if (sensitiveFile(value)) return true;
  }
  return false;
}

export function secretEgress(command) {
  const s = String(command ?? '');
  if (!targetsExternalNetwork(s)) return false;
  if (ENV_DUMP_ARG_RE.test(s)) return true;
  for (const line of s.split(/\n|;|&&/)) {
    const stages = pipelineStages(line);
    for (let i = 0; i < stages.length; i++) {
      const cmd = (stages[i][0] ?? '').replace(/^.*\//, '');
      if (NETWORK_SENDERS.has(cmd) && uploadsSecrets(stages[i])) return true;
      if (!readsSecrets(stages[i])) continue;
      if (stages.slice(i + 1).some((st) => NETWORK_SENDERS.has((st[0] ?? '').replace(/^.*\//, '')))) return true;
    }
  }
  return false;
}
