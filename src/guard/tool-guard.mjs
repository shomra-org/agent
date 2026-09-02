import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { resolveAgentIdentityHandle } from '../commands/agent-identity.mjs';
import { isMemoryPath, reportMemoryWrite } from '../commands/memory-scan.mjs';
import { breakerOpen, breakerReset, breakerTrip, guardTimeoutMs } from '../core/circuit-breaker.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { classifyConsequence, downrankCodeContext, grade, localScan } from '../detect/guard-signals.mjs';
import { WRITE_TOOLS, guardNeedsServer, guardTargetPath, guardText } from './classify.mjs';
import { emitGuardAsk, emitGuardDeny } from './emit.mjs';
import { guardPathAllowlisted } from './ignore.mjs';
import { screenModelLoad } from './model-load.mjs';
import { normalizeGuardInput } from './normalize.mjs';
import { envFlag, resolveAgentFlag } from './options.mjs';
import { buildGuardBody, reportGuardDecision } from './report.mjs';

const ALLOW_VERDICT = { verdict: 'ALLOW', top: null, findings: [] };

/**
 * ⚠ FAILING OPEN ON EVERYTHING IS AN ENFORCEMENT BYPASS AN ATTACKER BUYS WITH A
 * SLOW INPUT. The hook has to fail open - an agent that hard-stops on an
 * unreachable SaaS backend is one nobody keeps installed - but "open on every
 * call" means padding a command until the screen times out runs it unscreened,
 * which is cheaper than any evasion in the corpus.
 *
 * So the rung decides. A routine or material call still flows: that is the
 * promise that keeps the hook installed. A SEVERE one - a recursive delete, a
 * force push over a shared branch, a write into ~/.ssh - stops and ASKS.
 *
 * ⚠ IT ASKS, IT DOES NOT DENY. A deny during an outage is unappealable at 3am
 * and gets the hook uninstalled, taking every other control with it. An ask
 * puts the human who is already sitting there in the loop and says plainly
 * that the call was NOT screened, which is the honest sentence: we do not know
 * that this is dangerous, we know that we could not check.
 */
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

function memoryWriteContent(input) {
  if (typeof input.content === 'string') return input.content;
  if (typeof input.new_string === 'string') return input.new_string;
  return null;
}

async function recordMemoryWrite({ url, apiKey, input, normalized }) {
  const memoryPath = input.file_path || input.path;
  if (!memoryPath || !isMemoryPath(memoryPath) || breakerOpen()) return;

  const content = memoryWriteContent(input);
  if (content == null) return;

  await reportMemoryWrite(url, apiKey, {
    path: String(memoryPath).split(path.sep).join('/'),
    name: path.basename(String(memoryPath)),
    content,
    writer: 'AGENT',
    source: os.hostname(),
    actor: os.userInfo().username,
    sessionId: normalized.session_id,
  });
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
      /* ⚠ A 429 IS NOT AN OUTAGE, and treating it as one was a silent
       * enforcement bypass: tripping the breaker skips the server for the whole
       * cooldown, so one burst past the rate limit switched org policy, agent
       * identity and flow control off for thirty seconds - on the machine, with
       * nothing said. It means "we are here, come back", so it is retried once
       * against Retry-After and never counted against the breaker. */
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
    return decision;
  } catch (error) {
    clearTimeout(timer);
    breakerTrip();
    if (strict) emitGuardDeny(agent, `Shomra guard could not be reached (${error.message}); blocked by fail-closed policy.`);
    return onUnreachable(error.message, { breaker: true });
  }
}

/** Honours a seconds or an HTTP-date Retry-After; null when the server named none. */
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

export async function cmdToolGuard(flags) {
  const agent = resolveAgentFlag(flags);
  const agentId = resolveAgentIdentityHandle(flags);
  const strict = envFlag('SHOMRA_GUARD_STRICT');
  const alwaysEscalate = envFlag('SHOMRA_GUARD_ALWAYS_ESCALATE');
  const { apiKey, url } = resolveSettings(loadConfig());

  const normalized = normalizeGuardInput(agent, readHookPayload());
  const tool = (normalized.tool_name ?? '').trim();
  const input = normalized.tool_input ?? {};

  const local = localTierDisabled() ? ALLOW_VERDICT : screenLocally(normalized, tool, input);
  if (local.verdict === 'BLOCK') {
    await reportGuardDecision(url, apiKey, agentId, buildGuardBody(normalized, agent, 'BLOCK', local.top?.label));
    emitGuardDeny(agent, `Blocked on-machine by Shomra: ${local.top?.label || 'dangerous tool call'}.`);
  }

  await screenModelLoad(agent, tool, input, url);

  if (!apiKey) {
    if (strict) {
      emitGuardDeny(agent, 'Shomra is not configured on this machine (SHOMRA_GUARD_STRICT). Run: shomra init --key shm_…');
    }
    if (unscreenedSevere(normalized, tool, input)) askUnscreened(agent, 'Shomra is not configured on this machine');
    process.exit(0);
  }

  await recordMemoryWrite({ url, apiKey, input, normalized });

  /* ⚠ A SEVERE CALL IS ALWAYS WORTH THE ROUND TRIP. `guardNeedsServer` asks
   * which calls are worth escalating and answered NO for `git push --force
   * origin main` and `rm -rf` alike - so the most destructive calls in the
   * estate were graded by the offline tier and NOTHING ELSE: no org policy, no
   * capability check, no flow control, and no gate event to read afterwards. */
  const severe = unscreenedSevere(normalized, tool, input);
  const escalate = alwaysEscalate || severe || local.verdict === 'FLAG' || guardNeedsServer(tool, input, !!agentId);
  if (!escalate) process.exit(0);

  /* Every path out of here that did NOT get a server verdict goes through this
   * one door, so a new way of failing cannot quietly skip the rung check. */
  const onUnreachable = (why) => {
    if (severe) askUnscreened(agent, why);
    return process.exit(0);
  };

  if (!strict && breakerOpen()) onUnreachable('the guard is in its backoff window after an earlier failure');

  const flagged = local.verdict === 'FLAG';
  const decision = await requestServerDecision({
    url,
    apiKey,
    agentId,
    agent,
    strict,
    onUnreachable,
    body: buildGuardBody(normalized, agent, flagged ? 'FLAG' : undefined, flagged ? local.top?.label : undefined),
  });

  enforceServerDecision(agent, decision);
  process.exit(0);
}
