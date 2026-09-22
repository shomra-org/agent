import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { resolveAgentIdentityHandle } from '../commands/agent-identity.mjs';
import { isMemoryPath, reportMemoryWrite } from '../commands/memory-scan.mjs';
import { breakerOpen, breakerReset, breakerTrip, guardTimeoutMs } from '../core/circuit-breaker.mjs';
import { CONFIG_DIR } from '../core/config.mjs';
import { makeLedgerStore } from './ledger.mjs';
import { MAX_POST_CONTENT, memoryWritesFor, postEditContents, recordLedger, sha256 } from './memory-write.mjs';
import { memoryReportBase, reportOutOfBand } from './memory-report.mjs';
import { readSubjectTypes, rememberSubjectTypes, subjectBearingPath, subjectEscalation } from './subject-preclassify.mjs';
import { artifactKindFor } from './artifact-paths.mjs';
import { gateMachine } from '../core/api-client.mjs';
import { VERSION } from '../core/version.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { classifyConsequence, downrankCodeContext, grade, localScan } from '../detect/guard-signals.mjs';
import { recordVerdict, telemetryContext } from '../telemetry/record.mjs';
import { SHELL_TOOLS_RE, WRITE_TOOLS, callSubjectTypes, guardNeedsServer, guardTargetPath, guardText, shellCommandOf } from './classify.mjs';
import { emitGuardAsk, emitGuardDeny } from './emit.mjs';
import { guardPathAllowlisted } from './ignore.mjs';
import { screenModelLoad } from './model-load.mjs';
import { normalizeGuardInput } from './normalize.mjs';
import { envFlag, resolveAgentFlag } from './options.mjs';
import { recordSelftest, selftestField } from './selftest-marker.mjs';
import { buildGuardBody, reportGuardDecision } from './report.mjs';

const ALLOW_VERDICT = { verdict: 'ALLOW', top: null, findings: [] };


function failOpenOnSevere() {
  return envFlag('SHOMRA_GUARD_FAILOPEN_SEVERE');
}

function unscreenedSevere(normalized, tool, input) {
  if (failOpenOnSevere()) return false;
  return classifyConsequence({
    tool,
    args: guardText(tool, input),
    isShell: !WRITE_TOOLS.has(tool) && typeof input?.command === 'string',
  }) === 'severe';
}


function ledger() {
  return makeLedgerStore(CONFIG_DIR, { version: VERSION });
}

function countUnscreened(reason) {
  try {
    ledger().count(localTierDisabled() ? 'unscreened' : 'local', reason);
  } catch {
  }
}

function sendLedger() {
  try {
    const store = ledger();
    store.close();
    const env = store.envelope();
    pendingLedger = env.gaps ?? [];
    return env;
  } catch {
    return undefined;
  }
}

let pendingLedger = [];

function ackLedger() {
  if (!pendingLedger.length) return;
  try {
    ledger().ack(pendingLedger);
  } catch {
  }
  pendingLedger = [];
}

function askUnscreened(agent, why) {
  emitGuardAsk(
    agent,
    `Shomra could not screen this call (${why}), and it is a destructive one - a delete, a force push, `
    + 'or a write to a file that survives the session. Nothing has judged it: approve it only if you meant it. '
    + 'Set SHOMRA_GUARD_FAILOPEN_SEVERE=1 to let these through unscreened.',
  );
}

function readHookPayload() {
  try {
    return JSON.parse(fs.readFileSync(0, 'utf8') || '{}');
  } catch {
    return process.exit(0);
  }
}

function localTierDisabled() {
  return process.env.SHOMRA_GUARD_LOCAL === '0'
    || String(process.env.SHOMRA_GUARD_LOCAL).toLowerCase() === 'false';
}

function screenLocally(normalized, tool, input) {
  const scan = localScan(guardText(tool, input));
  const isWrite = WRITE_TOOLS.has(tool);
  const allowlisted = isWrite && guardPathAllowlisted(normalized.cwd, guardTargetPath(normalized));

  let findings = scan.findings;
  if (allowlisted) findings = [];
  else if (isWrite) findings = downrankCodeContext(scan.findings);

  const top = findings.find((finding) => finding.severity === 'CRITICAL') || findings[0] || null;
  return { ...grade(findings), top, findings };
}

function recordToolVerdict(tctx, { agent, normalized, tool, input, verdict, local, decidedBy, consequence }) {
  const shell = SHELL_TOOLS_RE.test(tool) || typeof input?.command === 'string' || Array.isArray(input?.command) || Array.isArray(input?.argv);
  recordVerdict({
    channel: 'tool',
    agent,
    tool,
    verdict,
    findings: local.findings,
    decidedBy,
    consequence,
    command: shell ? shellCommandOf(input) : null,
    target: WRITE_TOOLS.has(tool) ? guardTargetPath(normalized) : null,
    text: guardText(tool, input),
    at: local.top?.at,
    session: normalized.session_id,
    latencyMs: performance.now(),
  }, tctx);
}

const READ_TOOLS_RE = /^(read|read_file|view|open_file|cat)$/i;

async function recordMemoryWrite({ url, apiKey, tool, input, normalized }) {
  if (breakerOpen()) return;

  if (READ_TOOLS_RE.test(tool || '')) {
    const target = input.file_path || input.path || input.target_file;
    if (!target || !isMemoryPath(target)) return;
    const abs = path.resolve(normalized.cwd || process.cwd(), String(target));
    let current = null;
    try {
      current = fs.readFileSync(abs, 'utf8');
    } catch {
      return;
    }
    await reportOutOfBand(url, apiKey, abs, current, normalized);
    return;
  }

  const writes = memoryWritesFor(tool, input, { cwd: normalized.cwd }).filter((w) => w.path && isMemoryPath(w.path));
  for (const w of writes) {
    await reportOutOfBand(url, apiKey, w.path, w.before, normalized);
    await reportMemoryWrite(url, apiKey, {
      ...memoryReportBase(w.path, normalized),
      content: w.content,
      writer: 'AGENT',
      source: os.hostname(),
      contentBasis: w.basis,
    });
    recordLedger(w.path, [w.before != null ? sha256(w.before) : null, w.basis === 'whole' ? sha256(w.content) : null]);
  }
}

function reportUnauthenticated(agent, status, strict) {
  process.stderr.write(
    `[shomra] guard NOT enforced: the backend rejected this API key (HTTP ${status}). `
    + 'Local Tier-0 screening still ran; org policy, agent identity and flow control did not. '
    + 'Re-enroll with `shomra init --key <key>`.\n',
  );
  if (strict) {
    emitGuardDeny(agent, `Shomra guard could not authenticate (HTTP ${status}); blocked by fail-closed policy.`);
  }
  process.exit(0);
}

async function requestServerDecision({ url, apiKey, agentId, body, agent, strict, retried, onUnreachable }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), guardTimeoutMs());
  try {
    const response = await fetch(`${url}/gate/tool-call`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shomra-Key': apiKey,
        ...(agentId ? { 'X-Shomra-Agent': agentId } : {}),
        Connection: 'close',
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!response.ok) {
      if (response.status === 401 || response.status === 403) reportUnauthenticated(agent, response.status, strict);
      if (response.status === 429) {
        const wait = retryAfterMs(response);
        if (wait !== null && !retried) {
          clearTimeout(timer);
          await sleep(wait);
          return requestServerDecision({ url, apiKey, agentId, body, agent, strict, retried: true, onUnreachable });
        }
        clearTimeout(timer);
        return onUnreachable('rate limited', { breaker: false });
      }
      throw new Error(`HTTP ${response.status}`);
    }
    const decision = await response.json();
    breakerReset();
    ackLedger();
    return decision;
  } catch (error) {
    clearTimeout(timer);
    breakerTrip();
    if (strict) emitGuardDeny(agent, `Shomra guard could not be reached (${error.message}); blocked by fail-closed policy.`);
    return onUnreachable(error.message, { breaker: true });
  }
}

function retryAfterMs(response) {
  const raw = response.headers?.get?.('retry-after');
  if (!raw) return null;
  const secs = Number(raw);
  if (Number.isFinite(secs)) return Math.min(Math.max(secs, 0), 5) * 1000;
  const when = Date.parse(raw);
  return Number.isFinite(when) ? Math.min(Math.max(when - Date.now(), 0), 5000) : null;
}

const sleep = (ms) => new Promise((done) => { setTimeout(done, ms); });

function enforceServerDecision(agent, decision) {
  if (decision?.hold) {
    emitGuardAsk(agent, decision.reason || 'Held for approval by Shomra - waiting on a reviewer. Retry once it’s approved.');
  }
  if (decision?.decision === 'BLOCK') {
    emitGuardDeny(agent, decision.reason || 'Blocked by Shomra security policy.');
  }
}

/** ⚠ Bounded BEFORE the read: a 2 GB file named by an Edit must not be pulled into memory to be refused. */
function boundedRead(p) {
  if (fs.statSync(p).size > MAX_POST_CONTENT) throw new Error('too large to send');
  return fs.readFileSync(p, 'utf8');
}

/**
 * The post-edit file of every governed path this call edits - see
 * `postEditContents`. ⚠ Built only for a call that is being escalated, never
 * on the local-only path, and never allowed to fail the call: a reconstruction
 * that throws sends nothing and the server grades the fragment as a fragment.
 */
export function postContentField(tool, input, normalized, read = boundedRead) {
  try {
    const post = postEditContents(tool, input, {
      cwd: normalized?.cwd,
      read,
      keep: (p) => subjectBearingPath(p) || !!artifactKindFor(String(p ?? '').replace(/\\/g, '/')),
    });
    return post.length ? { post_content: post } : {};
  } catch {
    return {};
  }
}

export async function cmdToolGuard(flags) {
  const agent = resolveAgentFlag(flags);
  const agentId = resolveAgentIdentityHandle(flags);
  const strict = envFlag('SHOMRA_GUARD_STRICT');
  const alwaysEscalate = envFlag('SHOMRA_GUARD_ALWAYS_ESCALATE');
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  const tctx = telemetryContext(cfg);

  const normalized = normalizeGuardInput(agent, readHookPayload());
  const tool = (normalized.tool_name ?? '').trim();
  const input = normalized.tool_input ?? {};

  const local = localTierDisabled() ? ALLOW_VERDICT : screenLocally(normalized, tool, input);
  const decidedBy = localTierDisabled() ? 'unscreened' : 'local';
  if (local.verdict === 'BLOCK') {
    recordSelftest({ stage: 'local-block', tool, reason: local.top?.label ?? 'dangerous tool call' });
    recordToolVerdict(tctx, { agent, normalized, tool, input, verdict: 'BLOCK', local, decidedBy });
    await reportGuardDecision(url, apiKey, agentId, buildGuardBody(normalized, agent, 'BLOCK', local.top?.label));
    emitGuardDeny(agent, `Blocked on-machine by Shomra: ${local.top?.label || 'dangerous tool call'}.`);
  }

  await screenModelLoad(agent, tool, input, url);

  if (!apiKey) {
    recordSelftest({ stage: 'not-configured', tool });
    if (strict) {
      emitGuardDeny(agent, 'Shomra is not configured on this machine (SHOMRA_GUARD_STRICT). Run: shomra init --key shm_…');
    }
    const severe = unscreenedSevere(normalized, tool, input);
    recordToolVerdict(tctx, {
      agent, normalized, tool, input, local,
      verdict: severe ? 'ASK' : local.verdict,
      decidedBy: severe ? 'consequence' : decidedBy,
      consequence: severe ? 'severe' : null,
    });
    if (severe) askUnscreened(agent, 'Shomra is not configured on this machine');
    process.exit(0);
  }

  await recordMemoryWrite({ url, apiKey, tool, input, normalized });


  const severe = unscreenedSevere(normalized, tool, input);
  /**
   * ⚠ The org's subject types come from the server's last answer, cached on
   * disk - reading them costs no round trip. Unknown (no answer yet, stale, an
   * older server) escalates every subject-bearing call: see `subject-preclassify`.
   */
  const subjectTypes = readSubjectTypes({ url });
  const subjectCall = subjectEscalation(callSubjectTypes(tool, input, { cwd: normalized.cwd }), subjectTypes);
  const escalate = alwaysEscalate || severe || local.verdict === 'FLAG' || subjectCall || guardNeedsServer(tool, input, !!agentId, { subjectTypes, cwd: normalized.cwd });
  if (!escalate) {
    recordSelftest({ stage: 'not-escalated', tool, subjectTypes, reason: 'the local tier decided this call alone - the server never saw it' });
    countUnscreened('not escalated - screened by the local tier only');
    process.exit(0);
  }

  /**
   * ⚠ A SUBJECT CALL FOLLOWS THE MACHINE'S FAIL MODE, and says so. There is no
   * org-level fail mode: `SHOMRA_GUARD_STRICT` is the setting. Strict skips the
   * breaker and DENIES when the server cannot answer (`requestServerDecision`);
   * the default fails open - and the ledger records that an org subject rule
   * was NOT evaluated, distinct from an ordinary unscreened call, so a breaker
   * window of unchecked installs is visible on the server once it answers.
   */
  const onUnreachable = (why) => {
    recordSelftest({ stage: 'unreachable', tool, reason: why });
    countUnscreened(subjectCall ? `${why} - org subject rules NOT evaluated` : why);
    if (severe) askUnscreened(agent, why);
    return process.exit(0);
  };

  if (!strict && breakerOpen()) onUnreachable('the guard is in its backoff window after an earlier failure');

  const flagged = local.verdict === 'FLAG';
  const post = postContentField(tool, input, normalized);
  /**
   * ⚠ A SELF-TEST CANARY CARRIES NO LEDGER. The envelope is ACKNOWLEDGED the
   * moment the server answers, and a canary is answered by the simulator, which
   * records nothing - so sending it would retire a real fail-open window that
   * nobody ever stored. The self-test proves the path; it must not consume the
   * evidence of an outage on the way.
   */
  const selftest = selftestField();
  const startedAt = Date.now();
  const decision = await requestServerDecision({
    url,
    apiKey,
    agentId,
    agent,
    strict,
    onUnreachable,
    body: {
      ...buildGuardBody(normalized, agent, flagged ? 'FLAG' : undefined, flagged ? local.top?.label : undefined),
      ...post,
      ...selftest,
      ...(selftest.selftest ? {} : { guard_ledger: sendLedger() }),
    },
  });

  recordSelftest({
    stage: 'answered',
    tool,
    latencyMs: Date.now() - startedAt,
    postContent: (post.post_content ?? []).map((p) => p.path),
    decision: decision?.decision ?? null,
    simulated: decision?.simulated === true,
    hold: !!decision?.hold,
    reason: typeof decision?.reason === 'string' ? decision.reason.slice(0, 400) : null,
    outcome: decision?.selftest ?? null,
  });

  if (decision && typeof decision === 'object') rememberSubjectTypes(decision.subjectTypes, { url });
  enforceServerDecision(agent, decision);
  process.exit(0);
}
