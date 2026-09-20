import { CANARY_KINDS } from './canaries.mjs';

/**
 *  WHAT ONE CANARY PROVED, AND WHAT IT DID NOT.
 *
 * Pure on purpose: every state below is a sentence somebody will act on, and the
 * one that costs the most to get wrong is the difference between "the hook never
 * saw this call" (POROUS - the matcher leaves a hole) and "the hook saw it and
 * decided it alone" (correct, when the org has no rule of that type). Both look
 * identical from the server, which is why they are decided here, on the machine,
 * against the org's live subject types.
 */

export const STATE = {
  ESCALATED: 'escalated',
  LOCAL: 'local',
  POROUS: 'porous',
  FAILED: 'failed',
  UNPROVEN: 'unproven',
};

export const OK_STATES = new Set([STATE.ESCALATED, STATE.LOCAL]);

/**
 * The subject types each canary could carry - the same pre-classification the
 * hook makes (`subject-preclassify.mjs`). ⚠ `null` means the call escalates
 * whatever the org's rules say: an `mcp__` call and an MCP install always do.
 */
export const CANARY_SUBJECTS = {
  'shell-install': ['package', 'remote-script'],
  'powershell-install': ['package', 'remote-script'],
  'write-dockerfile': ['image', 'container', 'remote-script', 'package'],
  'edit-manifest': ['package', 'remote-script'],
  'apply-patch': ['image', 'container', 'remote-script', 'package'],
  'mcp-exec': null,
  'mcp-connect': null,
};

/**
 * ⚠ AN ORG WITH NO RULE OF THIS TYPE IS *SUPPOSED* TO DECIDE THE CALL LOCALLY.
 * Grading that as a hole would make every self-test fail on a fresh org and
 * teach everyone to ignore the result. An UNKNOWN set escalates everything, by
 * the same rule the hook itself follows.
 */
export function expectsEscalation(canary, subjectTypes) {
  const types = CANARY_SUBJECTS[canary];
  if (!types) return true;
  if (!Array.isArray(subjectTypes)) return true;
  return types.some((t) => subjectTypes.includes(t));
}

const answerOf = (receipts) => receipts.find((r) => r.stage === 'answered') ?? null;
const stageOf = (receipts) => receipts[receipts.length - 1]?.stage ?? null;

/**
 * @param {{canary:string, expectEscalation:boolean, result:{receipts:object[], spawnError:string|null, code:number|null, ms:number}, hookStale?:string|null}} args
 */
export function assessCanary({ canary, expectEscalation, result, hookStale = null }) {
  const kind = CANARY_KINDS[canary] ?? { title: canary, tool: 'tool' };
  const base = { canary, title: kind.title, tool: kind.tool, ms: result.ms ?? null, expectEscalation };
  const row = (state, statement, extra = {}) => ({ ...base, state, statement, ...extra });

  if (result.spawnError) {
    return row(STATE.POROUS, `The installed hook could not be run: ${result.spawnError}. A hook the agent cannot spawn screens nothing, and the agent runs the call anyway.`);
  }
  if (!result.receipts?.length) {
    if (hookStale) {
      return row(STATE.UNPROVEN, `The hook ran but reported nothing about this canary - ${hookStale}. An older hook has no self-test seam, so this says nothing either way.`);
    }
    return row(STATE.POROUS, 'The hook produced no record of this call at all - it never reached the screen. Check the matcher and the hook command.');
  }

  const stage = stageOf(result.receipts);
  const answer = answerOf(result.receipts);
  const latency = answer?.latencyMs ?? result.ms ?? null;

  if (stage === 'local-block') {
    const why = result.receipts.find((r) => r.stage === 'local-block')?.reason;
    return row(STATE.LOCAL, `Refused on-machine by the local tier (${why ?? 'dangerous tool call'}) - the hook is in path and nothing reached the server.`);
  }
  if (stage === 'not-configured') {
    return row(STATE.FAILED, 'This machine has no Shomra credentials, so the call was screened locally only and no org policy was applied. Run `shomra init --key shm_… --url <backend>`.');
  }
  if (stage === 'not-escalated') {
    return expectEscalation
      ? row(STATE.POROUS, 'The hook saw this call and decided it locally, although this org has a live rule of the type it carries - the rule never saw the call.')
      : row(STATE.LOCAL, 'The hook saw this call and decided it locally. This org has no live runtime rule of the type it carries, so that is the correct answer.');
  }
  if (stage === 'unreachable') {
    const why = result.receipts.find((r) => r.stage === 'unreachable')?.reason;
    return row(STATE.FAILED, `The hook escalated and the server did not answer (${why ?? 'unreachable'}). Org policy did not run on this call.`, { latencyMs: latency });
  }

  if (!answer) return row(STATE.POROUS, `The hook stopped at "${stage}" and never reached a verdict.`);

  if (!answer.simulated) {
    return row(STATE.FAILED, 'The server processed this canary as a LIVE call - the self-test nonce was not accepted. Nothing is wrong with the hook; the call was enforced and recorded as a real one.', {
      decision: answer.decision ?? null,
      latencyMs: latency,
    });
  }

  const simulated = answer.outcome ?? null;
  if (simulated && simulated.decision && answer.decision && simulated.decision !== answer.decision) {
    return row(STATE.FAILED, `The hook enforced ${answer.decision} while the server's simulator decided ${simulated.decision} for the same action under this org's live rules.`, {
      decision: answer.decision,
      simulatedDecision: simulated.decision,
      latencyMs: latency,
    });
  }

  if (CANARY_KINDS[canary]?.post && !(answer.postContent ?? []).length) {
    return row(STATE.FAILED, 'The call was escalated without the post-edit file. An edit carries only the replaced lines, so the org\'s rules graded a fragment as if it were the whole file.', {
      decision: answer.decision ?? null,
      latencyMs: latency,
    });
  }

  return row(STATE.ESCALATED, `Escalated and answered ${answer.decision ?? 'ALLOW'}${simulated?.decidedBy ? ` by ${simulated.decidedBy}` : ''}${(answer.postContent ?? []).length ? `, with the post-edit ${answer.postContent.join(', ')}` : ''}.`, {
    decision: answer.decision ?? null,
    simulatedDecision: simulated?.decision ?? null,
    decidedBy: simulated?.decidedBy ?? null,
    outcome: simulated?.outcome ?? null,
    subjects: simulated?.subjects ?? null,
    postContent: answer.postContent ?? [],
    latencyMs: latency,
  });
}

/** Worst-wins: one porous canary is the reading for the vendor, never an average. */
export function rollUpVendor(staticRow, canaries) {
  const states = canaries.map((c) => c.state);
  const porous = staticRow.state === 'porous' || states.includes(STATE.POROUS);
  const failed = states.includes(STATE.FAILED);
  const absent = staticRow.state === 'absent';
  const stale = staticRow.state === 'stale';
  const state = absent ? 'absent' : stale ? 'stale' : porous ? 'porous' : failed ? 'failed' : states.includes(STATE.UNPROVEN) ? 'unproven' : 'pass';
  return {
    vendor: staticRow.vendor,
    label: staticRow.label,
    state,
    static: staticRow,
    canaries,
    escalated: states.filter((s) => s === STATE.ESCALATED).length,
    total: canaries.length,
  };
}

export function exitCodeFor(vendors, { strict = false } = {}) {
  const bad = vendors.some((v) => v.state === 'porous' || v.state === 'failed' || v.state === 'stale');
  if (bad) return 1;
  if (!strict) return 0;
  const warn = vendors.some((v) => v.state === 'unproven' || v.state === 'absent' || v.canaries.some((c) => c.state === STATE.LOCAL));
  return warn ? 1 : 0;
}
