import os from 'node:os';
import path from 'node:path';

export const HOME = os.homedir();

export const ARTIFACT_KINDS = ['skill', 'command', 'subagent', 'hook'];

export const MAX_DEPTH = 6;

export const MAX_DIRS = 4_000;

export const MAX_ARTIFACTS = 400;

export const MAX_FILE_BYTES = 64_000;

export const MAX_BUNDLED = 20;

export const MAX_TOTAL_BYTES = 4_000_000;

export const IGNORE_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', 'coverage', '__pycache__',
  '.venv', 'venv', 'site-packages', '.next', '.turbo', 'target',

  'projects', 'todos', 'statsig', 'shell-snapshots', 'history', 'logs', 'cache',
]);

export const TEXT_EXTS = new Set([
  'md', 'mdc', 'markdown', 'txt', 'toml', 'json', 'jsonc', 'yaml', 'yml',
  'sh', 'bash', 'zsh', 'ps1', 'bat', 'cmd', 'py', 'js', 'mjs', 'cjs', 'ts',
  'rb', 'pl', 'lua', 'sql', 'env', 'cfg', 'ini', 'conf',
]);

export const extOf = (p) => {
  const b = path.basename(p);
  const i = b.lastIndexOf('.');
  return i > 0 ? b.slice(i + 1).toLowerCase() : '';
};
