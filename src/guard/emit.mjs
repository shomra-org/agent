import { dim } from '../core/terminal.mjs';

export function emitGuardDeny(agent, reason, userNote, stopped) {
  if (agent === 'windsurf') {
    process.stderr.write(reason);
    process.exit(2);
  }
  const bodies = {
    cursor: () => ({ permission: 'deny', user_message: reason, agent_message: reason }),
    copilot: () => ({ permissionDecision: 'deny', permissionDecisionReason: reason }),
    gemini: () => ({ decision: 'deny', reason }),
    codex: () => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } }),
    cline: () => ({ decision: 'deny', reason, hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } }),
    claude: () => ({ ...(stopped ? { continue: false, stopReason: stopped } : {}), hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason }, ...(userNote ? { systemMessage: userNote } : {}) }),
  };
  process.stdout.write(JSON.stringify((bodies[agent] || bodies.claude)()));
  process.exit(0);
}

export function stoppedNote(stopped) {
  if (!stopped || typeof stopped.sentence !== 'string') return undefined;
  const clean = stopped.sentence.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, ' ').trim().slice(0, 400);
  return clean ? `Shomra stopped this session. ${clean}` : undefined;
}

export function confirmationNote(confirmation) {
  if (confirmation?.state !== 'WAITING' || !confirmation.code) return undefined;
  const shown = (v, n) => String(v ?? '').replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, '').slice(0, n);
  return `Check your phone: confirm ${shown(confirmation.tool, 80) || 'this call'} with code ${shown(confirmation.code, 8)}. The agent can retry once you have.`;
}

export function emitResultBlock(agent, reason) {

  if (agent === 'windsurf') {
    console.error(dim(reason));
    process.exit(0);
  }
  const bodies = {
    cursor: () => ({ permission: 'deny', user_message: reason, agent_message: reason }),
    copilot: () => ({ permissionDecision: 'deny', permissionDecisionReason: reason }),
    gemini: () => ({ decision: 'deny', reason }),
    codex: () => ({ decision: 'block', reason, hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: reason } }),
    cline: () => ({ decision: 'block', reason, hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: reason } }),
    claude: () => ({ decision: 'block', reason, hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: reason } }),
  };
  process.stdout.write(JSON.stringify((bodies[agent] || bodies.claude)()));
  process.exit(0);
}

export function emitGuardAsk(agent, reason) {
  const bodies = {
    cursor: () => ({ permission: 'ask', user_message: reason, agent_message: reason }),
    copilot: () => ({ permissionDecision: 'ask', permissionDecisionReason: reason }),
    gemini: () => ({ decision: 'ask', reason }),
    codex: () => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: reason } }),
    cline: () => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: reason } }),
    claude: () => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: reason } }),
  };

  if (agent === 'windsurf' || !bodies[agent]) { process.stderr.write(reason + '\n'); process.exit(0); }
  process.stdout.write(JSON.stringify(bodies[agent]()));
  process.exit(0);
}
