import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CONFIG_DIR } from '../core/config.mjs';
import { SHELL_TOOLS_RE, WRITE_TOOLS, guardTouchedPaths, patchTextOf, shellCommandOf, shellWritePaths } from './classify.mjs';
import { SHOMRA_ANY_HOOK_RE } from '../agents/hook-command.mjs';
import { postEditContents } from './memory-write.mjs';

const HOME_PREFIX = /^(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE)(?=[\\/]|$)/i;
const MUTATE_VERB = /(?:^|[\s;&|(])(?:rm|rmdir|unlink|shred|truncate|mv|cp|install|dd|chmod|chown|chattr|ln|tee|sed|perl|remove-item|del|erase|rd|set-content|add-content|clear-content|out-file|new-item|copy-item|move-item|rename-item)(?=\s)|>/i;
const STATE_REF = /(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE)[\\/]\.shomra(?=[\\/\s"';|&)]|$)/i;
const ASK_CAPABLE = new Set(['claude', 'cursor', 'copilot', 'gemini', 'codex', 'cline']);
const MUTATING_LEAVES = new Set(['move_file', 'delete_file', 'remove_file', 'rename_file', 'copy_file']);
const HOOK_FILE_RE = /(?:^|[\\/])(?:\.claude[\\/]settings(?:\.local)?\.json|\.codex[\\/]hooks\.json|\.gemini[\\/]settings\.json|\.cursor[\\/]hooks\.json|\.codeium[\\/]windsurf[\\/]hooks\.json|\.windsurf[\\/]hooks\.json|\.copilot[\\/]hooks[\\/][^\\/]+\.json|\.github[\\/]hooks[\\/][^\\/]+\.json|\.cline[\\/]hooks\.json)$/i;
const IGNORE_FILE_RE = /(?:^|[\\/])\.shomraignore$/i;
const DISABLE_HOOKS_RE = /["']?disableAllHooks["']?\s*:\s*true\b/i;
const GUARD_ENV_RE = /["']?SHOMRA_(?:GUARD_LOCAL|GUARD_IGNORE|MODEL_GUARD|MCP_SCREEN|URL|GUARD_TIMEOUT_MS|GUARD_BREAKER_MS)["']?\s*:/i;

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

function proposedText(tool, input, target, cwd, read) {
  const i = input ?? {};
  if (typeof i.content === 'string' && !Array.isArray(i.edits)) return i.content;
  if (typeof i.file_text === 'string') return i.file_text;
  const post = postEditContents(tool, i, { cwd, read, keep: () => true });
  const hit = post.find((x) => path.resolve(cwd || process.cwd(), x.path) === target);
  return hit ? hit.content : null;
}

export function guardHookTamper(tool, input = {}, { cwd = process.cwd(), home = os.homedir(), read = (p) => fs.readFileSync(p, 'utf8') } = {}) {
  const abs = (p) => path.resolve(cwd || process.cwd(), String(p).trim().replace(/^["']|["']$/g, '').replace(HOME_PREFIX, home));
  const command = SHELL_TOOLS_RE.test(tool || '') || typeof input?.command === 'string' || Array.isArray(input?.argv) ? shellCommandOf(input) : '';
  const direct = mutatesPaths(tool) || patchTextOf(tool, input) ? guardTouchedPaths(tool, input) : [];
  const viaShell = command ? shellWritePaths(command) : [];
  const hits = [];
  const note = (p, why) => {
    if (!hits.some((h) => h.path === p)) hits.push({ path: p, why });
  };
  for (const p of [...direct, ...viaShell]) {
    const target = abs(p);
    if (IGNORE_FILE_RE.test(target)) {
      note(p, 'ignore-list');
      continue;
    }
    if (!HOOK_FILE_RE.test(target)) continue;
    let current;
    try {
      current = read(target);
    } catch {
      continue;
    }
    if (!SHOMRA_ANY_HOOK_RE.test(current)) continue;
    const next = direct.includes(p) ? proposedText(tool, input, target, cwd, read) : null;
    if (next === null) note(p, 'rewrites');
    else if (!SHOMRA_ANY_HOOK_RE.test(next)) note(p, 'removes-hook');
    else if (DISABLE_HOOKS_RE.test(next) && !DISABLE_HOOKS_RE.test(current)) note(p, 'disables-hooks');
    else if (GUARD_ENV_RE.test(next) && !GUARD_ENV_RE.test(current)) note(p, 'guard-env');
  }
  return hits.length ? { paths: hits.map((h) => h.path).slice(0, 5), why: hits[0].why } : null;
}

const HOOK_TAMPER_WHY = {
  'removes-hook': 'removes the Shomra guard hook from',
  'disables-hooks': 'sets disableAllHooks, which stops every hook including the Shomra guard, in',
  'guard-env': 'sets a SHOMRA_ variable that switches off or re-points the guard in',
  rewrites: 'rewrites, with no way to check the Shomra guard hook survives,',
  'ignore-list': 'edits the list of paths the Shomra guard skips,',
};

export function hookTamperReason(hit) {
  return `This call ${HOOK_TAMPER_WHY[hit.why] ?? 'changes'} ${hit.paths.join(', ')}. That hook is what screens every tool call this agent makes; with it gone, nothing screens the calls after this one. `
    + 'An agent has no reason to switch off the guard that screens it; approve only if you asked for exactly this.';
}

