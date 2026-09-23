import { targetsExternalNetwork } from './network.mjs';

export const VENDOR_INSTALLERS = [
  { host: 'sh.rustup.rs' },
  { host: 'bun.sh', path: '/install' },
  { host: 'deno.land', path: '/install.sh' },
  { host: 'deno.land', path: '/x/install/' },
  { host: 'astral.sh', path: '/uv/' },
  { host: 'astral.sh', path: '/ruff/' },
  { host: 'get.pnpm.io', path: '/install.sh' },
  { host: 'raw.githubusercontent.com', path: '/nvm-sh/nvm/' },
  { host: 'raw.githubusercontent.com', path: '/homebrew/install/' },
  { host: 'raw.githubusercontent.com', path: '/ohmyzsh/ohmyzsh/' },
  { host: 'raw.githubusercontent.com', path: '/helm/helm/' },
  { host: 'get.docker.com' },
  { host: 'install.python-poetry.org' },
  { host: 'bootstrap.pypa.io', path: '/get-pip.py' },
  { host: 'pyenv.run' },
  { host: 'sdk.cloud.google.com' },
  { host: 'fnm.vercel.app', path: '/install' },
  { host: 'get.volta.sh' },
  { host: 'starship.rs', path: '/install.sh' },
  { host: 'ollama.com', path: '/install.sh' },
  { host: 'tailscale.com', path: '/install.sh' },
  { host: 'get.k3s.io' },
  { host: 'deb.nodesource.com', path: '/setup_' },
  { host: 'rpm.nodesource.com', path: '/setup_' },
  { host: 'install.determinate.systems', path: '/nix' },
  { host: 'nixos.org', path: '/nix/install' },
  { host: 'dot.net', path: '/v1/dotnet-install.sh' },
  { host: 'get.sdkman.io' },
  { host: 'get.rvm.io' },
  { host: 'claude.ai', path: '/install.sh' },
  { host: 'mise.run' },
  { host: 'fly.io', path: '/install.sh' },
  { host: 'cli.doppler.com', path: '/install.sh' },
  { host: 'get.pulumi.com' },
  { host: 'rclone.org', path: '/install.sh' },
  { host: 'foundry.paradigm.xyz' },
];

const URL_RE = /https?:\/\/[^\s'"`;|)&<>]+/gi;

export function isVendorInstallerUrl(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.protocol !== 'https:') return false;
  const host = u.hostname.toLowerCase();
  const path = u.pathname.toLowerCase();
  return VENDOR_INSTALLERS.some((v) => v.host === host && (!v.path || path.startsWith(v.path)));
}

export function vendorInstallerLine(line) {
  const urls = String(line).match(URL_RE) ?? [];
  return urls.length > 0 && urls.every(isVendorInstallerUrl);
}

const BIN_PREFIX = String.raw`(?:\/(?:usr\/)?(?:local\/)?bin\/)?`;

const SUBSTITUTION_RE = new RegExp(
  [
    String.raw`(?:^|[\s;&|(])(?:(?:sudo|doas)\s+(?:-\S+\s+)*)?${BIN_PREFIX}(?:(?:ba|z|k|da)?sh|source|\.)\s+(?:-\S+\s+)*<\(\s*(?:curl|wget)\b`,
    String.raw`(?:^|[\s;&|(])(?:(?:sudo|doas)\s+(?:-\S+\s+)*)?${BIN_PREFIX}(?:(?:ba|z|k|da)?sh|python[0-9.]*|node|perl|ruby|php)\s+(?:-\S+\s+)*-(?:c|e|E|r)\s+["']?(?:\$\(|\x60)\s*(?:curl|wget)\b`,
    String.raw`(?:^|[\s;&|(])eval\s+["']?(?:\$\(|\x60)\s*(?:curl|wget)\b`,
  ].join('|'),
  'i',
);

export function runsSubstitutedDownload(line) {
  return SUBSTITUTION_RE.test(String(line));
}

export const SUBSTITUTION_SIGNAL_RE = SUBSTITUTION_RE;

const SUDO_VALUE_FLAGS = new Set(['-u', '-g', '-C', '-h', '-p', '-U', '-r', '-t', '-D', '-R', '-T', '--user', '--group', '--host', '--prompt', '--role', '--type', '--chdir', '--chroot', '--command-timeout']);
const ENV_VALUE_FLAGS = new Set(['-u', '--unset', '-C', '--chdir', '-S', '--split-string']);
const WRAPPERS = new Set(['nohup', 'time', 'command', 'builtin']);
const ASSIGNMENT_RE = /^\s*[A-Za-z_]\w*=(?:"[^"\n]*"|'[^'\n]*'|[^\s"']*)(?=\s|$)/;
const WORD_RE = /^\s*(\S+)/;

export function stripCommandPrefixes(stage) {
  let rest = String(stage);
  for (let guard = 0; guard < 64; guard++) {
    const assign = ASSIGNMENT_RE.exec(rest);
    if (assign) {
      rest = rest.slice(assign[0].length);
      continue;
    }
    const word = WORD_RE.exec(rest);
    if (!word) break;
    const w = word[1];
    const name = w.replace(/^.*\//, '');
    if (name === 'sudo' || name === 'doas' || name === 'env') {
      const valueFlags = name === 'env' ? ENV_VALUE_FLAGS : SUDO_VALUE_FLAGS;
      let after = rest.slice(word[0].length);
      for (let k = 0; k < 64; k++) {
        const flag = WORD_RE.exec(after);
        if (!flag || !flag[1].startsWith('-')) break;
        after = after.slice(flag[0].length);
        const bare = flag[1].split('=')[0];
        if (valueFlags.has(bare) && !flag[1].includes('=')) {
          const value = WORD_RE.exec(after);
          if (value) after = after.slice(value[0].length);
        }
      }
      let probe = after;
      for (let m = ASSIGNMENT_RE.exec(probe); m; m = ASSIGNMENT_RE.exec(probe)) probe = probe.slice(m[0].length);
      if (!probe.trim()) break;
      rest = after;
      continue;
    }
    if (WRAPPERS.has(name)) {
      if (!rest.slice(word[0].length).trim()) break;
      rest = rest.slice(word[0].length);
      continue;
    }
    break;
  }
  return rest.trim();
}

const PIPE_SOURCE_RE = /\b(curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod)\b/i;

const PIPE_TRANSFORM_RE = /\b(base64|xxd|od|tr|rev|gunzip|gzip|zcat|bunzip2|unxz|xz|funzip|openssl|uudecode|gpg|sed|awk|cut|dd|dos2unix)\b/i;

const PIPE_SHELL_SINK_RE = new RegExp(String.raw`^(sudo\s+)?${BIN_PREFIX}(sh|bash|zsh|ksh|dash|ash|busybox\s+sh)\b`, 'i');

const PIPE_INTERP_SINK_RE = new RegExp(String.raw`^(sudo\s+)?${BIN_PREFIX}(python[0-9.]*|perl|ruby|node|php|iex|invoke-expression|source)\b(?:\s+-\S*)*\s*$`, 'i');

const PIPE_INTERP_STDIN_RE = new RegExp(String.raw`^${BIN_PREFIX}(python[0-9.]*|perl|ruby|node|php)\b(?:\s+-[\w-]+)*\s+-(?:\s|$)`, 'i');

export function classifyStage(stage) {
  const raw = String(stage).trim();
  if (!raw) return 'other';
  const s = stripCommandPrefixes(raw);
  if (PIPE_SHELL_SINK_RE.test(s)) return 'shell-sink';
  if (PIPE_INTERP_SINK_RE.test(s) || PIPE_INTERP_STDIN_RE.test(s)) return 'interp-sink';
  if (PIPE_SOURCE_RE.test(s)) return 'source';
  if (PIPE_TRANSFORM_RE.test(s)) return 'transform';
  return 'other';
}

export function splitPipeStages(line) {
  return String(line).split(/(?<!\|)\|(?!\|)/);
}

export function pipesDownloadIntoInterpreter(line) {
  const stages = splitPipeStages(line);
  if (stages.length < 2) return false;
  const kinds = stages.map(classifyStage);
  for (let i = 0; i < stages.length; i++) {
    if (kinds[i] !== 'source') continue;
    for (let j = i + 1; j < stages.length; j++) {
      if (kinds[j] === 'shell-sink' || kinds[j] === 'interp-sink') return true;
    }
  }
  return false;
}

export function fetchExecShape(line) {
  if (runsSubstitutedDownload(line)) return 'substitution';
  if (pipesDownloadIntoInterpreter(line)) return 'pipe';
  return null;
}

export const PIPE_TO_SHELL_RE = new RegExp(
  String.raw`\b(curl|wget)\b[^\n|]{0,200}\|\s*(?:(?:sudo|doas)(?:\s+-[ugChpUrtDRT]\s+[^\s-]\S*|\s+-[\w-]+(?:=\S*)?)*\s+)?${BIN_PREFIX}(?:ba|z|k|da)?sh\b`,
  'i',
);

export const MULTI_STAGE_NAME = 'Multi-stage fetch-to-execute pipeline';

export function scanPipelineTaint(text) {
  if (!text) return [];
  for (const rawLine of String(text).split(/\n/)) {
    const stages = splitPipeStages(rawLine);
    if (stages.length < 2) continue;
    if (vendorInstallerLine(rawLine)) continue;
    const kinds = stages.map(classifyStage);
    for (let i = 0; i < stages.length; i++) {
      if (kinds[i] !== 'source') continue;
      if (!targetsExternalNetwork(stages[i])) continue;
      for (let j = i + 1; j < stages.length; j++) {
        const k = kinds[j];
        if (k !== 'shell-sink' && k !== 'interp-sink') continue;
        const adjacencyCovered = k === 'shell-sink' && j - i === 1 && PIPE_TO_SHELL_RE.test(`${stages[i]}|${stages[j]}`);
        if (adjacencyCovered) break;
        return [{ id: 'multi-stage-fetch-exec', name: MULTI_STAGE_NAME, re: /.^/, severity: 'CRITICAL' }];
      }
    }
  }
  return [];
}
