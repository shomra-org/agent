import fs from 'node:fs';
import { markRan } from './approvals.mjs';
import { SHELL_TOOLS_RE, shellCommandOf } from './command-text.mjs';
import { normalizeGuardInput } from './normalize.mjs';
import { resolveAgentFlag } from './options.mjs';

function readHookPayload() {
  try {
    return JSON.parse(fs.readFileSync(0, 'utf8') || '{}');
  } catch {
    return process.exit(0);
  }
}

export function recordRun(normalized) {
  const command = shellCommandOf(normalized?.tool_input ?? {});
  if (command) markRan(normalized?.session_id, command);
  return SHELL_TOOLS_RE.test(String(normalized?.tool_name ?? '').trim());
}

export async function cmdResultGuard(flags) {
  const agent = resolveAgentFlag(flags);
  const payload = readHookPayload();
  const normalized = normalizeGuardInput(agent, payload);
  if (recordRun(normalized)) return process.exit(0);
  const { screenToolResult } = await import('./result-screen.mjs');
  return screenToolResult(agent, payload, normalized);
}
