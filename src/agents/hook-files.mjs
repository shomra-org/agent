import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { SHOMRA_ANY_HOOK_RE, shomraHookRe } from './hook-command.mjs';

function agentHookFiles(agent) {
  const home = os.homedir();
  const cwd = process.cwd();
  switch (agent) {
    case 'claude': return [path.join(home, '.claude', 'settings.json'), path.join(cwd, '.claude', 'settings.json')];
    case 'codex': return [path.join(home, '.codex', 'hooks.json'), path.join(cwd, '.codex', 'hooks.json')];
    case 'gemini': return [path.join(home, '.gemini', 'settings.json'), path.join(cwd, '.gemini', 'settings.json')];
    case 'cursor': return [path.join(home, '.cursor', 'hooks.json'), path.join(cwd, '.cursor', 'hooks.json')];
    case 'windsurf': return [path.join(home, '.codeium', 'windsurf', 'hooks.json'), path.join(cwd, '.windsurf', 'hooks.json')];
    case 'copilot': return [path.join(home, '.copilot', 'hooks', 'shomra.json'), path.join(cwd, '.github', 'hooks', 'shomra.json')];
    case 'cline': return [path.join(home, '.cline', 'hooks.json'), path.join(cwd, '.cline', 'hooks.json')];
    case 'aider': return [path.join(home, '.aider.conf.yml'), path.join(cwd, '.aider.conf.yml')];
    default: return [];
  }
}

export function agentHookInstalled(agent) {
  return agentHookFiles(agent).filter((f) => {
    try {
      const text = fs.readFileSync(f, 'utf8');
      if (agent === 'aider') return /shomra llm guard/i.test(text);
      return SHOMRA_ANY_HOOK_RE.test(text);
    } catch {
      return false;
    }
  });
}

export function hasGroupedHook(list, verb) {
  const re = shomraHookRe(verb);
  return Array.isArray(list) && list.some((g) => Array.isArray(g.hooks) && g.hooks.some((h) => re.test(String(h.command || ''))));
}

export function hasFlatHook(list) {
  return Array.isArray(list) && list.some((h) => SHOMRA_ANY_HOOK_RE.test(String(h.command || '')));
}
