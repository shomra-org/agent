import { redactLocally } from '../detect/local-redact.mjs';

const MAX_INPUT = 8_000;
const MAX_SHAPE = 600;
const MAX_WORDS = 80;
const MAX_DEPTH = 2;

const KNOWN = new Set(`
sh bash zsh dash ksh fish csh tcsh pwsh powershell cmd python python2 python3 node nodejs deno bun ruby perl php lua java javac go rustc dotnet osascript
npm npx pnpm pnpx yarn pip pip3 pipx uv uvx poetry conda mamba micromamba gem bundle composer cargo brew apt apt-get dpkg yum dnf rpm apk pacman snap flatpak choco winget scoop nix nix-env
git gh hg svn git-lfs
curl wget nc ncat netcat socat ssh scp sftp rsync ftp tftp telnet nslookup dig host ping traceroute openssl ssh-keygen ssh-add ssh-copy-id http https aria2c
ls cat head tail less more cp mv rm rmdir mkdir touch ln chmod chown chgrp find grep egrep fgrep rg ag sed awk gawk cut sort uniq wc tr tee du df stat file tar zip unzip gzip gunzip bzip2 xz 7z dd shred truncate mktemp realpath basename dirname readlink diff patch install
ps kill pkill killall top htop systemctl service launchctl crontab at sudo doas su env export set unset alias source eval exec id whoami uname hostname date sleep echo printf true false test which whereis type history clear nohup time timeout nice xargs setsid watch strace chroot runuser stdbuf
cd pushd popd read wait trap exit return shift local declare readonly command builtin [ [[ ulimit umask
docker podman docker-compose nerdctl kubectl helm kind minikube k9s kubeseal aws gcloud gsutil bq az terraform tofu terragrunt pulumi ansible ansible-playbook vault consul nomad packer serverless sam cdk firebase vercel netlify heroku fly flyctl doctl wrangler
make cmake ninja gradle gradlew mvn ant jest vitest mocha pytest tox tsc eslint prettier webpack vite esbuild rollup turbo nx lerna
base64 xxd od hexdump gpg security keychain defaults reg certutil iptables ufw nft setenforce auditctl chattr mount umount modprobe insmod useradd usermod userdel passwd visudo
jq yq sqlite3 psql mysql mongo mongosh redis-cli code cursor open xdg-open start pbcopy pbpaste clip
del erase rd copy xcopy robocopy move ren dir net netsh sc schtasks wmic bitsadmin mshta rundll32 regsvr32 cscript wscript icacls takeown vssadmin wevtutil bcdedit
invoke-webrequest invoke-restmethod invoke-expression iex iwr irm start-process set-executionpolicy remove-item get-content set-content add-content out-file new-item copy-item move-item get-childitem write-output write-host expand-archive add-mppreference set-mppreference new-object
`.trim().split(/\s+/));

const WRAPPERS = new Set(['sudo', 'doas', 'env', 'nohup', 'time', 'timeout', 'nice', 'xargs', 'exec', 'setsid', 'watch', 'strace', 'chroot', 'runuser', 'stdbuf', 'command', 'builtin']);

const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'csh', 'tcsh']);

const INTERPRETER_CODE_FLAGS = {
  python: ['-c'], python2: ['-c'], python3: ['-c'], node: ['-e', '--eval', '-p', '--print'], nodejs: ['-e', '--eval'],
  deno: ['eval'], bun: ['-e', '--eval'], ruby: ['-e'], perl: ['-e', '-E'], php: ['-r'], lua: ['-e'],
  pwsh: ['-c', '-command', '-encodedcommand', '-enc', '-e'], powershell: ['-c', '-command', '-encodedcommand', '-enc', '-e'],
  osascript: ['-e'], cmd: ['/c', '/k'],
};

const SUBCOMMAND_DEPTH = {
  git: 1, 'git-lfs': 1, gh: 2, hg: 1, svn: 1, npm: 1, pnpm: 1, yarn: 1, bun: 1, deno: 1, pip: 1, pip3: 1, pipx: 1, uv: 1, poetry: 1, conda: 1, mamba: 1,
  gem: 1, bundle: 1, composer: 1, cargo: 1, go: 1, dotnet: 1, brew: 1, apt: 1, 'apt-get': 1, dpkg: 1, yum: 1, dnf: 1, apk: 1, pacman: 1, snap: 1,
  flatpak: 1, choco: 1, winget: 1, scoop: 1, nix: 1, docker: 1, podman: 1, 'docker-compose': 1, nerdctl: 1, kubectl: 2, helm: 1, kind: 1, minikube: 1,
  aws: 2, gcloud: 2, gsutil: 1, bq: 1, az: 2, terraform: 1, tofu: 1, terragrunt: 1, pulumi: 1, vault: 1, consul: 1, nomad: 1, packer: 1, serverless: 1,
  sam: 1, cdk: 1, firebase: 1, vercel: 1, netlify: 1, heroku: 1, fly: 1, flyctl: 1, doctl: 2, wrangler: 1, systemctl: 1, service: 0, launchctl: 1,
  security: 1, defaults: 1, reg: 1, openssl: 1, gpg: 0, crontab: 0, gradle: 1, gradlew: 1, mvn: 1, npx: 0, pnpx: 0, uvx: 0,
};

const SUBCOMMAND_RE = /^[a-z][a-z0-9-]{0,31}$/;

const JS_RUNNERS = new Set(['npm', 'pnpm', 'yarn', 'bun', 'deno']);

const JS_SUBCOMMANDS = new Set('install i add remove rm uninstall un up update upgrade run run-script exec dlx x test t start build publish pack link unlink audit outdated init create why info view config login logout whoami ci version cache store list ls global workspace workspaces rebuild prune dedupe patch fund doctor explain set-script task compile fmt lint'.split(' '));

const POWERSHELL = new Set(['pwsh', 'powershell', 'invoke-webrequest', 'invoke-restmethod', 'invoke-expression', 'iex', 'iwr', 'irm', 'start-process', 'set-executionpolicy', 'remove-item', 'get-content', 'set-content', 'add-content', 'out-file', 'new-item', 'copy-item', 'move-item', 'get-childitem', 'write-output', 'write-host', 'expand-archive', 'add-mppreference', 'set-mppreference', 'new-object']);

const REMOTE_LOGIN = new Set(['ssh', 'scp', 'sftp', 'rsync', 'ssh-copy-id', 'telnet', 'ftp']);

const ASSIGNING = new Set(['export', 'declare', 'local', 'readonly', 'env', 'set']);

const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);

const CHMOD_MODE_RE = /^(?:[0-7]{3,4}|[ugoa]*[+=-][rwxXst]+(?:,[ugoa]*[+=-][rwxXst]+)*)$/;

const STANDARD_VARS = new Set(['HOME', 'PATH', 'PWD', 'OLDPWD', 'USER', 'LOGNAME', 'SHELL', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'TERM', 'EDITOR', 'CI', 'IFS', 'RANDOM', 'UID', 'EUID']);

const SECRET_VAR_RE = /TOKEN|SECRET|PASS(?:WD|WORD)?|(?:^|_)KEY(?:$|_)|APIKEY|CRED|AUTH|SESSION|COOKIE|PRIVATE/i;

const SENSITIVE_ASSIGN = new Set(['PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH', 'NODE_OPTIONS', 'NODE_PATH', 'PYTHONPATH', 'PYTHONSTARTUP', 'PYTHONHOME', 'BASH_ENV', 'ENV', 'PROMPT_COMMAND', 'GIT_SSH_COMMAND', 'GIT_SSH', 'GIT_ASKPASS', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy', 'NPM_CONFIG_REGISTRY', 'npm_config_registry', 'PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'AWS_PROFILE', 'AWS_DEFAULT_REGION', 'KUBECONFIG', 'DOCKER_HOST', 'SHOMRA_GUARD_LOCAL', 'SHOMRA_GUARD_STRICT']);

const FILE_EXT = new Set('js mjs cjs ts tsx jsx json jsonc yaml yml toml ini cfg conf md txt sh bash zsh ps1 psm1 bat cmd py pyc rb go rs java kt c cc cpp h hpp cs php pl lua swift env lock xml html htm css scss pem key crt cer p12 pfx der log sql db sqlite csv tsv parquet zip tar gz tgz bz2 xz 7z rar whl jar war exe msi dll so dylib bin pkl pickle pt pth ckpt onnx safetensors gguf h5 keras ipynb dockerfile tf tfvars hcl service plist desktop'.split(' '));

const PUBLIC_HOSTS = [
  'raw.githubusercontent.com', 'gist.githubusercontent.com', 'objects.githubusercontent.com', 'github.com', 'githubusercontent.com', 'gitlab.com', 'bitbucket.org',
  'registry.npmjs.org', 'npmjs.org', 'npmjs.com', 'yarnpkg.com', 'pypi.org', 'files.pythonhosted.org', 'pythonhosted.org', 'crates.io', 'rubygems.org', 'proxy.golang.org', 'go.dev',
  'huggingface.co', 'hf.co', 'docker.io', 'ghcr.io', 'quay.io', 'gcr.io', 'amazonaws.com', 'googleapis.com', 'googleusercontent.com', 'windows.net', 'azurewebsites.net',
  'cloudflare.com', 'jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com', 'pastebin.com', 'paste.ee', 'hastebin.com', 'transfer.sh', 'file.io', '0x0.st', 'webhook.site',
  'requestbin.com', 'pipedream.net', 'ngrok.io', 'ngrok-free.app', 'ngrok.app', 'trycloudflare.com', 'localtunnel.me', 'loca.lt', 'serveo.net', 'discord.com', 'discordapp.com',
  'api.telegram.org', 'telegram.org', 'hooks.slack.com', 'slack.com', 'oast.fun', 'oast.pro', 'oast.live', 'interact.sh', 'burpcollaborator.net', 'dropbox.com',
  'dropboxusercontent.com', 'mega.nz', 'bit.ly', 'tinyurl.com', 'anthropic.com', 'openai.com', 'sh.rustup.rs', 'get.docker.com', 'deb.nodesource.com',
];

const METADATA_HOSTS = new Set(['169.254.169.254', 'metadata.google.internal', '100.100.100.200', '[fd00:ec2::254]', 'metadata']);

const OPERATOR_RE = /^(?:\d?>&\d*-?|&>>?|\d?>>?\|?|<<<|<<-|<<|\d?<&?\d*|\|\||\|&|\||&&|;;|;|&|\(|\))/;

function matchOperator(src, i) {
  const m = OPERATOR_RE.exec(src.slice(i, i + 6));
  if (!m) return null;
  if (/^\d/.test(m[0]) && i > 0 && /[\w.$-]/.test(src[i - 1])) return null;
  return m[0];
}

function expectsTarget(op) {
  return /^(?:\d?>{1,2}\|?|&>>?|\d?<|\d?>&)$/.test(op);
}

function readBalanced(src, i, open, close) {
  let depth = 0;
  for (let j = i; j < src.length; j++) {
    if (src[j] === '\\') { j++; continue; }
    if (src[j] === open) depth++;
    else if (src[j] === close && --depth === 0) return j;
  }
  return src.length - 1;
}

function lex(src) {
  const words = [];
  const heredocs = [];
  const literalBackslash = /(?:^|[\s"'=])[A-Za-z]:\\/.test(src);
  let i = 0;
  while (i < src.length && words.length < MAX_WORDS * 2) {
    const c = src[i];
    if (c === '\n') {
      words.push({ op: ';' });
      i++;
      for (const delim of heredocs.splice(0)) {
        const end = new RegExp(`(^|\\n)[ \\t]*${delim.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[ \\t]*(\\n|$)`).exec(src.slice(i));
        i = end ? i + end.index + end[0].length : src.length;
      }
      continue;
    }
    if (c === ' ' || c === '\t' || c === '\r') { i++; continue; }
    if (c === '#' && (i === 0 || /\s/.test(src[i - 1]))) {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    const op = matchOperator(src, i);
    if (op) {
      i += op.length;
      if (op === '<<' || op === '<<-') {
        const m = /^\s*(['"]?)([A-Za-z_][\w-]*)\1/.exec(src.slice(i));
        if (m) {
          heredocs.push(m[2]);
          i += m[0].length;
          words.push({ op: '<<' }, { heredoc: true });
          continue;
        }
      }
      words.push({ op });
      continue;
    }
    let text = '';
    let quoted = false;
    const subs = [];
    while (i < src.length) {
      const ch = src[i];
      if (/\s/.test(ch) || matchOperator(src, i)) break;
      if (ch === '\\' && !literalBackslash) { text += src[i + 1] ?? ''; i += 2; continue; }
      if (src.startsWith('$((', i)) {
        const end = src.indexOf('))', i + 3);
        const stop = end === -1 ? src.length : end + 2;
        text += src.slice(i, stop);
        i = stop;
        continue;
      }
      if (ch === "'") {
        const end = src.indexOf("'", i + 1);
        const stop = end === -1 ? src.length : end;
        text += src.slice(i + 1, stop);
        quoted = true;
        i = stop + 1;
        continue;
      }
      if (ch === '"') {
        let j = i + 1;
        while (j < src.length && src[j] !== '"') {
          if (src[j] === '\\') { j += 2; continue; }
          if (src.startsWith('$(', j)) {
            const end = readBalanced(src, j + 1, '(', ')');
            subs.push(src.slice(j + 2, end));
            j = end + 1;
            continue;
          }
          if (src[j] === '`') {
            const end = src.indexOf('`', j + 1);
            const stop = end === -1 ? src.length : end;
            subs.push(src.slice(j + 1, stop));
            j = stop + 1;
            continue;
          }
          j++;
        }
        text += src.slice(i + 1, j);
        quoted = true;
        i = j + 1;
        continue;
      }
      if (src.startsWith('$(', i) && !src.startsWith('$((', i)) {
        const end = readBalanced(src, i + 1, '(', ')');
        subs.push(src.slice(i + 2, end));
        text += src.slice(i, end + 1);
        i = end + 1;
        continue;
      }
      if (ch === '`') {
        const end = src.indexOf('`', i + 1);
        const stop = end === -1 ? src.length : end;
        subs.push(src.slice(i + 1, stop));
        text += src.slice(i, stop + 1);
        i = stop + 1;
        continue;
      }
      if (src.startsWith('${', i)) {
        const end = readBalanced(src, i + 1, '{', '}');
        text += src.slice(i, end + 1);
        i = end + 1;
        continue;
      }
      text += ch;
      i++;
    }
    words.push({ text, quoted, subs });
  }
  return words;
}

function publicHost(host) {
  for (const h of PUBLIC_HOSTS) if (host === h || host.endsWith(`.${h}`)) return h;
  return null;
}

function hostClass(host) {
  const h = host.toLowerCase();
  if (!h) return 'none';
  if (METADATA_HOSTS.has(h)) return 'metadata';
  if (/^(?:localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0|host\.docker\.internal)$/.test(h)) return 'loopback';
  if (/^(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)$/.test(h)) return 'private';
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h) || h.startsWith('[')) return 'ip';
  if (/\.(?:local|internal|corp|lan|intranet|home\.arpa)$/.test(h)) return 'internal';
  return publicHost(h) ?? 'domain';
}

function urlShape(token) {
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^@/?#]*@)?(\[[^\]]*\]|[^/:?#]*)/i.exec(token);
  if (!m) return '<url>';
  const scheme = m[1].toLowerCase();
  const known = ['http', 'https', 'ftp', 'ssh', 'git', 's3', 'gs', 'file', 'ws', 'wss', 'sftp', 'data'].includes(scheme) ? scheme : 'other';
  const cls = scheme === 'file' ? 'local' : hostClass(m[3] ?? '');
  return `<url:${known}:${cls}${m[2] ? ':userinfo' : ''}>`;
}

function looksLikePath(t) {
  if (/^(?:\/|~|\.{1,2}\/|[A-Za-z]:[\\/]|\\\\|%[A-Z]+%)/.test(t)) return true;
  if (/[\\/]/.test(t)) return true;
  const ext = /\.([A-Za-z0-9]{1,12})$/.exec(t)?.[1]?.toLowerCase();
  return !!ext && FILE_EXT.has(ext);
}

function pathShape(token) {
  const t = token.replace(/\\/g, '/');
  const low = t.toLowerCase();
  if (/^\/+\*?$/.test(low) || /^[a-z]:\/?\*?$/.test(low) || /^\/\*(?:\s|$)/.test(low)) return '<path:root>';
  if (/(?:^|\/)\.ssh(?:\/|$)|authorized_keys$|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$/.test(low)) return '<path:ssh>';
  if (/(?:^|\/)\.(?:aws|azure|kube|docker|gnupg|git-credentials|netrc|npmrc|pypirc|pgpass|vault-token)(?:\/|$)|\/\.config\/(?:gcloud|gh|op)(?:\/|$)|\/keychains?\//.test(low)) return '<path:credentials>';
  if (/(?:^|\/)\.env(?:\.[\w-]+)?$/.test(low)) return '<path:env-file>';
  if (/(?:^|\/)\.(?:bashrc|zshrc|profile|bash_profile|zprofile|zshenv|bash_login|bash_logout)$|\/config\.fish$|\/microsoft\.powershell_profile\.ps1$/.test(low)) return '<path:shell-rc>';
  if (/\/library\/launch(?:agents|daemons)\/|^\/etc\/(?:cron|systemd|rc\.local|init\.d)|\/\.config\/(?:autostart|systemd)\/|\/start menu\/programs\/startup/.test(low)) return '<path:autostart>';
  if (/(?:^|\/)\.(?:claude|cursor|codex|gemini|windsurf|vscode|continue)(?:\/|$)|(?:^|\/)(?:claude|agents|gemini)\.md$|\.mcp\.json$|\/\.shomra(?:\/|$)/.test(low)) return '<path:agent-config>';
  if (/^\/dev\/(?:tcp|udp)\//.test(low)) return '<path:net-device>';
  if (/^\/proc\//.test(low)) return '<path:proc>';
  if (/^\/(?:tmp|var\/tmp|dev\/shm)(?:\/|$)/.test(low)) return '<path:tmp>';
  if (/^\/(?:etc|usr|bin|sbin|boot|dev|lib|lib64|var|opt|system|library|private\/etc)(?:\/|$)|^[a-z]:\/windows\//.test(low)) return '<path:system>';
  const base = /^(?:~|\$home|\$\{home\}|%userprofile%)/.test(low) ? 'home' : /^(?:\/|[a-z]:\/|\/\/)/.test(low) ? 'abs' : 'rel';
  const ext = /\.([a-z0-9]{1,12})$/.exec(low)?.[1];
  return `<path:${base}${ext && FILE_EXT.has(ext) ? `:.${ext}` : ''}>`;
}

function varShape(token) {
  const name = /^\$\{?([A-Za-z_]\w*)/.exec(token)?.[1];
  if (!name) return '<var>';
  if (STANDARD_VARS.has(name)) return `$${name}`;
  return SECRET_VAR_RE.test(name) ? '<var:secret>' : '<var>';
}

function assignShape(name, value) {
  return `${SENSITIVE_ASSIGN.has(name) ? name : SECRET_VAR_RE.test(name) ? '<var:secret>' : '<var>'}=${value ? argShape(value) : ''}`;
}

function argShape(token, ctx = {}) {
  const t = String(token ?? '');
  if (!t) return '<str>';
  if (t.includes('[shomra:redacted:secret]')) return '<secret>';
  if (ctx.flag === '-H' || ctx.flag === '--header') {
    const header = /^([A-Za-z][A-Za-z0-9-]{1,40}):/.exec(t);
    if (header) return `<header:${header[1].toLowerCase()}>`;
  }
  if (ctx.quoted && /\s/.test(t)) return '<str>';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) return urlShape(t);
  const scp = /^(?:[\w.-]+@)?([\w.-]+\.[a-z]{2,}):[\w./~-]+(?:\.git)?$/i.exec(t);
  if (scp && !/^[a-z]:[\\/]/i.test(t)) return `<url:ssh:${hostClass(scp[1])}>`;
  const login = /^[\w.-]+@([\w.-]+|\[[^\]]+\])$/.exec(t);
  if (login && REMOTE_LOGIN.has(ctx.exec)) return `<login:${hostClass(login[1])}>`;
  if (login && /\.[a-z]{2,}$/i.test(login[1])) return '<email>';
  if (/^[\w.-]+@(?:[\d^~<>=*]|latest\b|next\b|beta\b)/i.test(t)) return '<pkg>';
  if (/^[*?.]+$/.test(t) && t.includes('*')) return t;
  if (t === '.' || t === '..') return '<path:rel>';
  if (t === '@-') return '@-';
  if (/^@[\w.-]+\/[\w.-]+(?:@[\w.^~<>=*-]+)?$/.test(t)) return '<pkg:scoped>';
  if (t.startsWith('@') && t.length > 1) return `@${argShape(t.slice(1), ctx)}`;
  if (HTTP_METHODS.has(t)) return t;
  if (ctx.exec === 'chmod' && CHMOD_MODE_RE.test(t)) return t;
  const volume = /^([^:\s]+):([^:\s]+)(?::[a-z,]+)?$/i.exec(t);
  if (volume && looksLikePath(volume[1]) && looksLikePath(volume[2])) return `${pathShape(volume[1])}:${pathShape(volume[2])}`;
  if (/^\$\{?[A-Za-z_]\w*\}?$/.test(t)) return varShape(t);
  if (/^\$\{?[A-Za-z_]\w*\}?[\\/]/.test(t)) return pathShape(t);
  if (/^-?\d+(?:\.\d+)?[kKmMgGtTsShHdD%]?$/.test(t)) return '<num>';
  if (/^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$/.test(t)) {
    const cls = hostClass(t.split(':')[0]);
    return `<ip:${cls === 'ip' ? 'public' : cls}>`;
  }
  if (/^[A-Za-z0-9+/]{40,}={0,2}$/.test(t) || /^[A-Za-z0-9_-]{60,}$/.test(t)) return '<b64>';
  if (/^(?:0x)?[0-9a-f]{16,}$/i.test(t)) return '<hex>';
  if (looksLikePath(t)) return pathShape(t);
  if (/^[\w-]+(?:\.[\w-]+)+(?::\d+)?$/.test(t) && /\.[a-z]{2,}(?::\d+)?$/i.test(t)) {
    const host = t.replace(/:\d+$/, '').toLowerCase();
    const cls = hostClass(host);
    return `<host:${cls}>`;
  }
  return '<str>';
}

function flagShape(token, ctx = {}) {
  const eq = token.indexOf('=');
  const name = eq === -1 ? token : token.slice(0, eq);
  if (/^--[A-Za-z][A-Za-z0-9-]{0,40}$/.test(name)) return eq === -1 ? name : `${name}=${argShape(token.slice(eq + 1), ctx)}`;
  if (/^-[A-Za-z]{1,5}-?$/.test(name) && eq === -1) return name;
  if (POWERSHELL.has(ctx.exec) && /^-[A-Za-z][A-Za-z0-9]{1,40}$/.test(name)) return eq === -1 ? name : `${name}=${argShape(token.slice(eq + 1), ctx)}`;
  if (/^-[A-Za-z]$/.test(name.slice(0, 2))) return `${name.slice(0, 2)}<attached>`;
  return '<flag>';
}

function executableName(text) {
  const base = text.replace(/\\/g, '/').split('/').pop().replace(/\.exe$/i, '');
  return base;
}

function shapeCommand(words, depth) {
  const out = [];
  let expect = 'exec';
  let exec = null;
  let subLeft = 0;
  let codeFlags = null;
  let shellFlag = false;
  let afterRedirect = false;
  let prevFlag = null;
  for (const w of words) {
    if (out.length >= MAX_WORDS) {
      out.push('…');
      break;
    }
    if (w.op) {
      out.push(w.op);
      prevFlag = null;
      afterRedirect = expectsTarget(w.op);
      if (!afterRedirect && w.op !== '<<' && w.op !== '<<<') {
        expect = 'exec';
        exec = null;
        subLeft = 0;
        codeFlags = null;
        shellFlag = false;
      }
      continue;
    }
    if (w.heredoc) {
      out.push('<heredoc>');
      continue;
    }
    const text = w.text ?? '';
    if (afterRedirect) {
      afterRedirect = false;
      out.push(/^&?\d$/.test(text) ? text : /^\/dev\/null$/.test(text) ? '/dev/null' : argShape(text));
      continue;
    }
    if (w.subs?.length && depth < MAX_DEPTH) {
      const inner = shapeText(w.subs[0], depth + 1);
      if (expect === 'exec') {
        out.push(`$(${inner})`);
        expect = 'args';
        continue;
      }
      out.push(`$(${inner})`);
      continue;
    }
    if (expect === 'exec') {
      const assign = /^([A-Za-z_]\w*)=(.*)$/s.exec(text);
      if (assign) {
        out.push(assignShape(assign[1], assign[2]));
        continue;
      }
      const name = executableName(text);
      const lower = name.toLowerCase();
      if (KNOWN.has(lower)) {
        out.push(lower);
        exec = lower;
        subLeft = SUBCOMMAND_DEPTH[lower] ?? 0;
        codeFlags = INTERPRETER_CODE_FLAGS[lower] ?? null;
        shellFlag = false;
        expect = WRAPPERS.has(lower) ? 'wrapped' : 'args';
      } else if (/^\$\{?[A-Za-z_]/.test(text)) {
        out.push(varShape(text));
        expect = 'args';
      } else if (looksLikePath(text)) {
        out.push(pathShape(text));
        expect = 'args';
      } else {
        out.push('<cmd>');
        expect = 'args';
      }
      continue;
    }
    if (expect === 'wrapped' && !w.quoted && !text.startsWith('-')) {
      const lower = executableName(text).toLowerCase();
      if (KNOWN.has(lower)) {
        out.push(lower);
        exec = lower;
        subLeft = SUBCOMMAND_DEPTH[lower] ?? 0;
        codeFlags = INTERPRETER_CODE_FLAGS[lower] ?? null;
        expect = WRAPPERS.has(lower) ? 'wrapped' : 'args';
        continue;
      }
      if (/^[A-Za-z_]\w*=/.test(text)) {
        out.push(assignShape(text.slice(0, text.indexOf('=')), text.slice(text.indexOf('=') + 1)));
        continue;
      }
    }
    if (shellFlag) {
      shellFlag = false;
      out.push(depth < MAX_DEPTH ? `"${shapeText(text, depth + 1)}"` : '<script>');
      continue;
    }
    if (codeFlags === 'next') {
      codeFlags = null;
      out.push(`<code:${exec}>`);
      continue;
    }
    const flagBefore = prevFlag;
    prevFlag = !w.quoted && text.startsWith('-') && !text.includes('=') ? text : null;
    if (!w.quoted && text.startsWith('-') && text.length > 1) {
      const lower = text.toLowerCase();
      if (SHELLS.has(exec) && /^-[a-z]*c[a-z]*$/.test(text)) {
        out.push(text);
        shellFlag = true;
        continue;
      }
      if (Array.isArray(codeFlags) && codeFlags.includes(lower)) {
        out.push(lower);
        codeFlags = 'next';
        continue;
      }
      out.push(flagShape(text, { exec }));
      continue;
    }
    if (ASSIGNING.has(exec) && !w.quoted && /^[A-Za-z_]\w*=/.test(text)) {
      out.push(assignShape(text.slice(0, text.indexOf('=')), text.slice(text.indexOf('=') + 1)));
      continue;
    }
    if (exec === 'eval' && depth < MAX_DEPTH) {
      out.push(`"${shapeText(text, depth + 1)}"`);
      continue;
    }
    if (exec === 'cmd' && /^\/[ck]$/i.test(text)) {
      out.push(text.toLowerCase());
      shellFlag = true;
      continue;
    }
    if (subLeft > 0 && !flagBefore && !w.quoted && SUBCOMMAND_RE.test(text) && !/\d{3,}/.test(text) && (!JS_RUNNERS.has(exec) || JS_SUBCOMMANDS.has(text))) {
      out.push(text);
      subLeft--;
      continue;
    }
    if (!flagBefore) subLeft = 0;
    out.push(argShape(text, { exec, quoted: w.quoted, flag: flagBefore }));
  }
  return out;
}

function shapeText(text, depth) {
  return shapeCommand(lex(String(text ?? '')), depth).join(' ').replace(/\s+/g, ' ').replace(/^(?:;\s*)+|(?:\s*;)+$/g, '').trim();
}

export function targetShape(target) {
  const t = typeof target === 'string' ? target.trim() : '';
  return t ? pathShape(t) : null;
}

export function commandShape(command) {
  const raw = typeof command === 'string' ? command : '';
  if (!raw.trim()) return null;
  const redacted = redactLocally(raw.slice(0, MAX_INPUT), { categories: ['secret'] }).text;
  const shape = shapeText(redacted, 0);
  if (!shape) return null;
  const clipped = shape.length > MAX_SHAPE ? `${shape.slice(0, MAX_SHAPE - 1)}…` : shape;
  return raw.length > MAX_INPUT ? `${clipped} …` : clipped;
}
