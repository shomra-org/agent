const HIJACK_LOADERS = [
  { keys: ['BASH_ENV'], key: 'BASH_ENV', governs: 'every non-interactive bash' },
  { keys: ['ZDOTDIR'], key: 'ZDOTDIR', governs: 'every zsh startup' },
  { keys: ['ENV'], key: 'ENV', governs: 'every sh startup', requires: /[/$]|\.sh\b/ },
  { keys: ['PROMPT_COMMAND'], key: 'PROMPT_COMMAND', governs: 'every bash prompt' },
  { keys: ['PYTHONSTARTUP'], key: 'PYTHONSTARTUP', governs: 'every interactive python' },
  { keys: ['PYTHONBREAKPOINT'], key: 'PYTHONBREAKPOINT', governs: 'python, at any breakpoint()' },

  { keys: ['NODE_OPTIONS'], key: 'NODE_OPTIONS', governs: 'every node process', requires: /(?:^|\s)--(?:require|import|experimental-loader|loader|env-file)\b|(?:^|\s)-r\s/, foreignOnly: true },
  { keys: ['PERL5OPT'], key: 'PERL5OPT', governs: 'every perl process', requires: /(?:^|\s)-[Mm]\S/, foreignOnly: true },
  { keys: ['RUBYOPT'], key: 'RUBYOPT', governs: 'every ruby process', requires: /(?:^|\s)-r\S/, foreignOnly: true },
  { keys: ['JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS'], key: 'JAVA_TOOL_OPTIONS', governs: 'every JVM', requires: /-(?:javaagent|agentpath|agentlib|Xbootclasspath)/i, foreignOnly: true },
  { keys: ['NODE_REPL_EXTERNAL_MODULE'], key: 'NODE_REPL_EXTERNAL_MODULE', governs: 'every node repl' },
  { keys: ['GIT_EXTERNAL_DIFF'], key: 'GIT_EXTERNAL_DIFF', governs: 'every git diff' },
  { keys: ['GIT_PROXY_COMMAND'], key: 'GIT_PROXY_COMMAND', governs: 'every git fetch over git://' },
  { keys: ['GIT_TEMPLATE_DIR'], key: 'GIT_TEMPLATE_DIR', governs: 'every git init / clone (hooks)' },
  { keys: ['GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM'], key: 'GIT_CONFIG_GLOBAL', governs: 'every git command' },
  { keys: ['LESSOPEN', 'LESSCLOSE'], key: 'LESSOPEN', governs: 'every less / pager invocation' },
];

const HIJACK_SLOTS = [
  { keys: ['GIT_PAGER'], key: 'GIT_PAGER', governs: 'every git command that pages' },
  { keys: ['GIT_EDITOR'], key: 'GIT_EDITOR', governs: 'every git commit / rebase' },
  { keys: ['GIT_SEQUENCE_EDITOR'], key: 'GIT_SEQUENCE_EDITOR', governs: 'every git rebase -i' },
  { keys: ['GIT_SSH', 'GIT_SSH_COMMAND'], key: 'GIT_SSH_COMMAND', governs: 'every git fetch / push over ssh' },
  { keys: ['GIT_ASKPASS', 'SSH_ASKPASS'], key: 'GIT_ASKPASS', governs: 'every credential prompt' },
  { keys: ['EDITOR', 'VISUAL'], key: 'EDITOR', governs: 'git, crontab, and anything that opens an editor' },
  { keys: ['PAGER', 'MANPAGER'], key: 'PAGER', governs: 'every command that pages' },
];

const HIJACK_PRELOADS = /\b(LD_PRELOAD|LD_AUDIT|DYLD_INSERT_LIBRARIES)\b/;

const GIT_EXEC_KEYS =
  /\b(core\.pager|core\.editor|core\.sshCommand|core\.fsmonitor|core\.hooksPath|core\.askpass|sequence\.editor|diff\.external|diff\.[\w-]+\.textconv|filter\.[\w-]+\.(?:clean|smudge|process)|merge\.[\w-]+\.driver|credential\.helper|uploadpack\.packObjectsHook)\b/i;

const GIT_ALIAS_KEY = /\balias\.[\w-]+\b/i;

const HIJACK_PLAIN_PROGRAM = /^[\w./-]{1,64}(?:\s+-{1,2}[\w-]{1,32}){0,4}$/;

const HIJACK_SHELLY = /[;&|`$(){}<>]|\s-c\s|(?<![.\w])(?:sh|bash|zsh|dash|python\d?|node|perl|ruby|eval)\b/i;

const HIJACK_WORLD_WRITABLE = /(^|[\s'"=:])(\/tmp\/|\/var\/tmp\/|\/dev\/shm\/|~\/\.cache\/|\$TMPDIR|\/private\/tmp\/)/i;

const HIJACK_ASSIGN =
  /(?:^|[\s;&|(]|\b(?:export|declare|typeset|setenv|set\s+-x)\s+)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*("([^"]*)"|'([^']*)'|[^\s;&|)]*)/g;

const HIJACK_GIT_CONFIG =
  /\bgit\s+config\s+(?:--(?:global|system|local|worktree|add|replace-all)\s+|--file\s+\S+\s+)*([\w.*-]+)\s+("[^"]*"|'[^']*'|\S+)/i;

const hijackUnquote = (raw) => String(raw ?? '').replace(/^["']|["']$/g, '');

function hijackForeignTarget(value) {
  if (HIJACK_SHELLY.test(value)) return true;
  for (const raw of String(value).split(/[\s,]+/)) {
    const token = raw.replace(/^--?[A-Za-z][\w-]*[=:]?/, '').replace(/^file:\/\//, '');
    if (/^~?\//.test(token)) return true;
  }
  return false;
}

const hijackLoaderSeverity = (v) => (!String(v).trim() ? 'MEDIUM' : HIJACK_SHELLY.test(v) || HIJACK_WORLD_WRITABLE.test(v) ? 'CRITICAL' : 'HIGH');

function hijackPathShadow(value) {
  const head = hijackUnquote(value).split(':')[0]?.trim();
  if (!head || /\$PATH/.test(head)) return null;
  if (/^(\.|\.\/|\$\{?PWD\}?|\$\{?CI_PROJECT_DIR\}?|\$\{?GITHUB_WORKSPACE\}?|node_modules|\$\{?HOME\}?\/\.(?:local|nvm|rbenv|pyenv|cargo|bun|deno|volta)\b|~\/\.(?:local|nvm|rbenv|pyenv|cargo|bun|deno|volta)\b)/i.test(head)) return null;
  if (!HIJACK_WORLD_WRITABLE.test(head) && !/^[^/$~]/.test(head)) return null;
  return {
    vector: 'path-shadow', key: 'PATH', governs: 'every command resolved by name',
    severity: HIJACK_WORLD_WRITABLE.test(head) ? 'HIGH' : 'MEDIUM', value: head,
    detail: `PATH is prepended with "${head}", which is outside the workspace. Every later command resolved by NAME - including any an allowlist names - can be shadowed from there.`,
  };
}

export function detectExecutionHijack(command) {
  const text = String(command ?? '');
  if (!text.trim()) return [];
  const out = [];
  for (const m of text.matchAll(HIJACK_ASSIGN)) {
    const key = m[1];
    const value = hijackUnquote(m[2] ?? '');
    if (key === 'PATH') {
      const p = hijackPathShadow(m[2] ?? '');
      if (p) out.push(p);
      continue;
    }
    const loader = HIJACK_LOADERS.find((l) => l.keys.includes(key));
    if (loader && (!loader.requires || loader.requires.test(value)) && (!loader.foreignOnly || hijackForeignTarget(value))) {
      out.push({
        vector: 'env-var', key: loader.key, governs: loader.governs, severity: hijackLoaderSeverity(value), value,
        detail: `${loader.key} names code that ${loader.governs} loads before doing anything else. Setting it turns an already-approved command into one that runs "${value || '(empty)'}" first - no dangerous command is ever issued.`,
      });
      continue;
    }
    if (HIJACK_PRELOADS.test(key)) {
      out.push({
        vector: 'env-var', key, governs: 'every dynamically linked process', severity: 'CRITICAL', value,
        detail: `${key} injects "${value}" into every process started afterwards, whatever the allowlist says about the command that starts it.`,
      });
      continue;
    }
    const slot = HIJACK_SLOTS.find((p) => p.keys.includes(key));
    if (slot && value && !HIJACK_PLAIN_PROGRAM.test(value.trim())) {
      out.push({
        vector: 'env-var', key: slot.key, governs: slot.governs, severity: HIJACK_SHELLY.test(value) ? 'CRITICAL' : 'HIGH', value,
        detail: `${slot.key} is set to "${value}", which is a command line rather than an editor or pager. ${slot.governs} will run it - the hijack rides an approved command, not a refused one.`,
      });
    }
  }
  for (const line of text.split(/[\n;]|&&|\|\|/)) {
    const m = HIJACK_GIT_CONFIG.exec(line);
    if (!m) continue;
    const key = m[1];
    const value = hijackUnquote(m[2].trim());
    const isAlias = GIT_ALIAS_KEY.test(key) && /^\s*!/.test(value);
    if (!GIT_EXEC_KEYS.test(key) && !isAlias) continue;
    const shelly = HIJACK_SHELLY.test(value) || HIJACK_WORLD_WRITABLE.test(value) || isAlias;
    if (!shelly && HIJACK_PLAIN_PROGRAM.test(value)) continue;
    out.push({
      vector: 'git-config', key,
      governs: isAlias ? `git ${key.split('.')[1]}` : 'every later git command that reaches this hook',
      severity: shelly ? 'CRITICAL' : 'HIGH', value,
      detail: `git config "${key}" is set to "${value}". Git executes this value, so every later git command - including ones an allowlist names - runs it. The configuration outlives the session.`,
    });
  }
  const seen = new Set();
  return out.filter((s) => (seen.has(`${s.vector}:${s.key}`) ? false : (seen.add(`${s.vector}:${s.key}`), true)));
}
