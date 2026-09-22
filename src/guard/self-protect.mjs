import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CONFIG_DIR } from '../core/config.mjs';
import { SHELL_TOOLS_RE, WRITE_TOOLS, guardTouchedPaths, patchTextOf, shellCommandOf, shellWritePaths } from './classify.mjs';

const HOME_PREFIX = /^(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE)(?=[\\/]|$)/i;
const MUTATE_VERB = /(?:^|[\s;&|(])(?:rm|rmdir|unlink|shred|truncate|mv|cp|install|dd|chmod|chown|chattr|ln|tee|sed|perl|remove-item|del|erase|rd|set-content|add-content|clear-content|out-file|new-item|copy-item|move-item|rename-item)(?=\s)|>/i;
const STATE_REF = /(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE)[\\/]\.shomra(?=[\\/\s"';|&)]|$)/i;
const ASK_CAPABLE = new Set(['claude', 'cursor', 'copilot', 'gemini', 'codex', 'cline']);
const MUTATING_LEAVES = new Set(['move_file', 'delete_file', 'remove_file', 'rename_file', 'copy_file']);

function mutatesPaths(tool) {
  const name = String(tool ?? '');
  const leaf = name.includes('__') ? name.slice(name.lastIndexOf('__') + 2) : name;
  return WRITE_TOOLS.has(name) || WRITE_TOOLS.has(leaf) || MUTATING_LEAVES.has(leaf.toLowerCase());
}

function within(root, target) {
  const rel = path.relative(root, target);
  return rel === '' || (!!rel && !rel.startsWith('..') && !path.isAbsolute(rel));
}

function real(p) {
  try {
    return fs.realpathSync(p);
  } catch {
    return null;
  }
}

export function insideGuardState(p, { cwd = process.cwd(), home = os.homedir(), stateDir = CONFIG_DIR } = {}) {
  if (typeof p !== 'string' || !p.trim()) return false;
  const raw = p.trim().replace(/^["']|["']$/g, '').replace(HOME_PREFIX, home);
  const abs = path.resolve(cwd || process.cwd(), raw);
  const roots = [path.resolve(stateDir), real(stateDir)].filter(Boolean);
  const targets = [abs, real(abs)].filter(Boolean);
  return roots.some((root) => targets.some((t) => within(root, t)));
}

export function guardStateTamper(tool, input = {}, opts = {}) {
  const writes = [];
  const patch = patchTextOf(tool, input);
  if (mutatesPaths(tool) || patch) writes.push(...guardTouchedPaths(tool, input));
  const command = SHELL_TOOLS_RE.test(tool || '') || typeof input?.command === 'string' || Array.isArray(input?.argv) ? shellCommandOf(input) : '';
  if (command) writes.push(...shellWritePaths(command));
  const hits = [...new Set(writes.filter((p) => insideGuardState(p, opts)))];
  if (!hits.length && command && MUTATE_VERB.test(command)) {
    const stateDir = opts.stateDir ?? CONFIG_DIR;
    const ref = STATE_REF.exec(command) ?? (command.toLowerCase().includes(stateDir.toLowerCase()) ? [stateDir] : null);
    if (ref) hits.push(ref[0]);
  }
  return hits.length ? { paths: hits.slice(0, 5) } : null;
}

export function tamperReason(hit) {
  return `This call changes Shomra's own guard state (${hit.paths.join(', ')}) - the settings, credential and breaker the firewall screening this agent depends on. `
    + 'An agent has no reason to edit the guard that screens it; approve only if you asked for exactly this.';
}

export function refuseOrAsk(agent, strict) {
  return strict || !ASK_CAPABLE.has(agent) ? 'deny' : 'ask';
}
