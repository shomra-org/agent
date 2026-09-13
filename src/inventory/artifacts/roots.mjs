import path from 'node:path';
import { HOME } from './limits.mjs';
import { EXTENSIONS_DIR_NAME, claudeDesktopDataDir } from './extensions.mjs';

const PLAT = process.platform;
const APPDATA = process.env.APPDATA || path.join(HOME, 'AppData', 'Roaming');
const XDG = PLAT === 'win32' ? APPDATA : path.join(HOME, '.config');
const CLAUDE_MANAGED = PLAT === 'win32' ? 'C:\\Program Files\\ClaudeCode' : PLAT === 'darwin' ? '/Library/Application Support/ClaudeCode' : '/etc/claude-code';

export function rulesRoots() {
  return [
    { vendor: 'claude-code', scope: 'user', dir: CLAUDE_MANAGED, managed: true },
    { vendor: 'qwen-code', scope: 'user', dir: path.join(HOME, '.qwen') },
    { vendor: 'roo', scope: 'user', dir: path.join(HOME, '.roo') },
    { vendor: 'kiro', scope: 'user', dir: path.join(HOME, '.kiro') },
    { vendor: 'augment', scope: 'user', dir: path.join(HOME, '.augment') },
    { vendor: 'junie', scope: 'user', dir: path.join(HOME, '.junie') },
    { vendor: 'cline', scope: 'user', dir: path.join(HOME, 'Documents', 'Cline') },
    { vendor: 'zed', scope: 'user', dir: path.join(XDG, PLAT === 'win32' ? 'Zed' : 'zed') },
    { vendor: 'goose', scope: 'user', dir: PLAT === 'win32' ? path.join(APPDATA, 'Block', 'goose', 'config') : path.join(HOME, '.config', 'goose') },
    { vendor: 'amp', scope: 'user', dir: path.join(HOME, '.config', 'amp') },
    { vendor: 'opencode', scope: 'user', dir: path.join(HOME, '.config', 'opencode') },
    { vendor: 'agents-md', scope: 'user', dir: path.join(HOME, '.agents') },
    { vendor: 'continue', scope: 'user', dir: path.join(HOME, '.continue') },
  ];
}

export function projectVendorRoots(cwd = process.cwd()) {
  return [
    { vendor: 'roo', scope: 'project', dir: path.join(cwd, '.roo') },
    { vendor: 'qwen-code', scope: 'project', dir: path.join(cwd, '.qwen') },
    { vendor: 'kiro', scope: 'project', dir: path.join(cwd, '.kiro') },
    { vendor: 'cline', scope: 'project', dir: path.join(cwd, '.clinerules') },
    { vendor: 'continue', scope: 'project', dir: path.join(cwd, '.continue') },
    { vendor: 'agents-md', scope: 'project', dir: path.join(cwd, '.agents') },
  ];
}

export function artifactRoots(cwd = process.cwd()) {
  return [
    ...rulesRoots(),
    ...projectVendorRoots(cwd),
    { vendor: 'claude-code', scope: 'user', dir: path.join(HOME, '.claude') },
    { vendor: 'claude-code', scope: 'project', dir: path.join(cwd, '.claude') },
    { vendor: 'cursor', scope: 'user', dir: path.join(HOME, '.cursor') },
    { vendor: 'cursor', scope: 'project', dir: path.join(cwd, '.cursor') },
    { vendor: 'codex', scope: 'user', dir: path.join(HOME, '.codex') },
    { vendor: 'codex', scope: 'project', dir: path.join(cwd, '.codex') },
    { vendor: 'gemini', scope: 'user', dir: path.join(HOME, '.gemini') },
    { vendor: 'gemini', scope: 'project', dir: path.join(cwd, '.gemini') },
    { vendor: 'windsurf', scope: 'user', dir: path.join(HOME, '.codeium', 'windsurf') },
    { vendor: 'windsurf', scope: 'project', dir: path.join(cwd, '.windsurf') },
    { vendor: 'opencode', scope: 'user', dir: path.join(HOME, '.opencode') },
    { vendor: 'opencode', scope: 'project', dir: path.join(cwd, '.opencode') },

    { vendor: 'copilot', scope: 'user', dir: path.join(HOME, '.copilot') },
    { vendor: 'copilot', scope: 'project', dir: path.join(cwd, '.github') },
    { vendor: 'claude-desktop', scope: 'user', dir: path.join(claudeDesktopDataDir(), EXTENSIONS_DIR_NAME) },
  ];
}
