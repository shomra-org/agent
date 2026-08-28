import path from 'node:path';
import { HOME } from './limits.mjs';

export function artifactRoots(cwd = process.cwd()) {
  return [
    { vendor: 'claude-code', scope: 'user', dir: path.join(HOME, '.claude') },
    { vendor: 'claude-code', scope: 'project', dir: path.join(cwd, '.claude') },
    { vendor: 'cursor', scope: 'user', dir: path.join(HOME, '.cursor') },
    { vendor: 'cursor', scope: 'project', dir: path.join(cwd, '.cursor') },
    { vendor: 'codex', scope: 'user', dir: path.join(HOME, '.codex') },
    { vendor: 'codex', scope: 'project', dir: path.join(cwd, '.codex') },
    { vendor: 'gemini', scope: 'user', dir: path.join(HOME, '.gemini') },
    { vendor: 'gemini', scope: 'project', dir: path.join(cwd, '.gemini') },
    { vendor: 'windsurf', scope: 'project', dir: path.join(cwd, '.windsurf') },
    { vendor: 'opencode', scope: 'user', dir: path.join(HOME, '.opencode') },
    { vendor: 'opencode', scope: 'project', dir: path.join(cwd, '.opencode') },

    { vendor: 'copilot', scope: 'project', dir: path.join(cwd, '.github') },
  ];
}
