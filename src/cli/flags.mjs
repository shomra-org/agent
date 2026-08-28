const BOOLEAN_FLAGS = new Set([
  'strict', 'json', 'sarif', 'fix', 'staged', 'changed', 'all', 'history', 'force',
  'apply', 'dry-run', 'global', 'local', 'trailer', 'evolve', 'report', 'init',
  'no-suppress', 'no-baseline', 'no-policy', 'no-index', 'adaptive',
  'fail-on-regression', 'fail-on-blocked', 'write', 'yes', 'stdin', 'quiet', 'help',
  'check', 'checklist', 'pre-receive', 'uninstall', 'save', 'list',
]);

const VALUE_FLAGS = new Set([
  'key', 'url', 'path', 'kind', 'name', 'project', 'agent', 'agent-id', 'min',
  'scenarios', 'objectives', 'turns', 'target', 'run', 'port', 'config', 'env',
  'command', 'base', 'repo', 'pr', 'token', 'sha', 'session', 'since', 'depth',
  'scope', 'writer', 'type', 'slug', 'framework', 'chunk-size', 'manifest',

  'fail-on',

  'subject', 'title', 'note', 'actor',

  'input',
]);

export const KNOWN_FLAGS = new Set([...BOOLEAN_FLAGS, ...VALUE_FLAGS]);

const REPEATABLE_FLAGS = new Set(['input']);

function setFlag(flags, name, value) {
  if (!REPEATABLE_FLAGS.has(name)) {
    flags[name] = value;
    return;
  }
  const prev = flags[name];
  flags[name] = prev === undefined ? value : [].concat(prev, value);
}

export function parseFlags(argv) {
  const flags = {};
  const positional = [];
  const unknown = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const body = a.slice(2);

      const eq = body.indexOf('=');
      if (eq !== -1) {
        const name = body.slice(0, eq);
        if (!KNOWN_FLAGS.has(name)) unknown.push(name);
        setFlag(flags, name, body.slice(eq + 1));
        continue;
      }
      if (!KNOWN_FLAGS.has(body)) {
        unknown.push(body);
        flags[body] = true;
        continue;
      }
      if (BOOLEAN_FLAGS.has(body)) {
        flags[body] = true;
        continue;
      }
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        setFlag(flags, body, next);
        i++;
      } else flags[body] = true;
    } else positional.push(a);
  }
  return { flags, positional, unknown };
}
