import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { VENDOR_KEYS, VENDOR_TOOLS, matcherCovers } from '../agents/vendor-tools.mjs';
import { api, machineInfo } from '../core/api-client.mjs';
import { breakerOpen } from '../core/circuit-breaker.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { bold, cyan, dim, gray, green, red, yellow } from '../core/terminal.mjs';
import { VERSION } from '../core/version.mjs';
import { envFlag } from '../guard/options.mjs';
import { readSubjectTypes, rememberSubjectTypes } from '../guard/subject-preclassify.mjs';
import { canariesFor, prepareCanaryDir } from '../selftest/canaries.mjs';
import { OK_STATES, STATE, assessCanary, exitCodeFor, expectsEscalation, rollUpVendor } from '../selftest/assess.mjs';
import { environmentChecks, installedVendors, staticCheck } from '../selftest/static-checks.mjs';
import { runCanary } from '../selftest/spawn-hook.mjs';

/**
 *  THE ONE THING A SERVER-SIDE SIMULATION CANNOT PROVE: that this machine's
 * agents actually reach the policy.
 *
 * A rule can be live, correct and tested on the server while every call on this
 * laptop walks past it - because the matcher in a settings file does not name
 * the vendor's shell tool, because the hook command points at a checkout that
 * was deleted, because the payload shape this vendor sends is unwrapped into
 * nothing. None of that is visible from the server: a machine whose hook never
 * fires and a machine whose agents are idle send exactly the same thing, which
 * is nothing.
 *
 * So this drives the REAL install - the command string out of the vendor's own
 * settings file, the payload shape the vendor really posts - and reports what
 * happened to each canary, including the cases where deciding locally was the
 * right answer.
 */

const STATE_ICON = {
  pass: green('✓'),
  escalated: green('✓'),
  local: gray('·'),
  porous: red('✗'),
  failed: red('✗'),
  stale: red('✗'),
  unproven: yellow('!'),
  absent: yellow('○'),
  ok: green('✓'),
};

function eventOf(vendor, payload) {
  return payload.hook_event_name ?? payload.agent_action_name ?? VENDOR_TOOLS[vendor]?.event ?? VENDOR_TOOLS[vendor]?.events?.[0]?.name ?? null;
}

function toolOf(payload) {
  return payload.tool_name ?? payload.toolName ?? null;
}

/**
 * The installed entry the vendor itself would run for this call.
 * ⚠ No entry means the call never reaches the hook - the same hole the static
 * matcher check reports, observed a second way.
 */
export function entryForCanary(vendor, installs, payload) {
  const event = eventOf(vendor, payload);
  const tool = toolOf(payload);
  const byEvent = installs.filter((i) => !i.event || !event || i.event === event);
  const pool = byEvent.length ? byEvent : [];
  return (
    pool.find((i) => i.matcher === null || !tool || matcherCovers(i.matcher, tool, tool)) ?? null
  );
}

function resolveVendors(flags) {
  const raw = String(flags.agent ?? 'all').toLowerCase().trim();
  if (raw === 'all' || raw === 'true') return installedVendors(VENDOR_KEYS);
  const asked = raw.split(',').map((s) => s.trim()).filter(Boolean);
  const unknown = asked.filter((a) => !VENDOR_KEYS.includes(a));
  if (unknown.length) {
    console.error(red('✗') + ` Unknown agent(s): ${unknown.join(', ')}. Supported: ${VENDOR_KEYS.join(', ')}, all.`);
    process.exit(EXIT_USAGE);
  }
  return asked;
}

async function startSession(url, apiKey, machine, vendors) {
  return api(url, apiKey, '/gate/selftest/start', { machine, agents: vendors, agentVersion: VERSION }, { timeoutMs: 15_000 });
}

/** Run every canary for one vendor against its own installed hook entries. */
async function runVendor({ vendor, statics, session, root, subjectTypes }) {
  const mark = `${session.marker}-${vendor}`;
  const files = prepareCanaryDir(root, mark);
  const receiptDir = path.join(root, 'receipts');
  fs.mkdirSync(receiptDir, { recursive: true });

  const rows = [];
  for (const c of canariesFor(vendor, { marker: mark, ...files })) {
    const entry = entryForCanary(vendor, statics.installs, c.payload);
    const expectEscalation = expectsEscalation(c.id, subjectTypes);
    if (!entry) {
      rows.push({
        canary: c.id,
        title: c.title,
        tool: c.tool,
        expectEscalation,
        state: STATE.POROUS,
        statement: `No installed hook entry covers ${toolOf(c.payload) ?? eventOf(vendor, c.payload)} - this call reaches no screen at all.`,
      });
      continue;
    }
    const result = await runCanary({
      command: entry.command,
      vendor,
      canary: c.id,
      payload: c.payload,
      cwd: files.dir,
      session: { nonce: session.nonce },
      receiptDir,
    });
    rows.push(assessCanary({ canary: c.id, expectEscalation, result, hookStale: entry.health?.stale ? entry.health.detail : null }));
  }
  return rows;
}

function printStatic(row) {
  const icon = STATE_ICON[row.state] ?? gray('·');
  console.log(`  ${icon} ${bold(row.label.padEnd(20))} ${dim(row.files[0] ?? 'no settings file')}`);
  console.log(`      ${row.state === 'ok' ? dim(row.statement) : row.statement}`);
  for (const m of row.missing ?? []) console.log(`      ${red('missing')} ${bold(m.name)} ${dim(`- ${m.why} run with nothing in front of them`)}`);
  for (const m of row.missingEvents ?? []) console.log(`      ${red('not wired')} ${bold(m.name)} ${dim(`- ${m.why}`)}`);
  if (row.state === 'porous' || row.state === 'absent' || row.state === 'stale') console.log(`      ${dim('fix:')} ${bold(row.fix)}`);
  for (const n of row.notes ?? []) console.log(`      ${dim(n)}`);
}

function printCanaries(rows) {
  for (const r of rows) {
    const icon = STATE_ICON[r.state] ?? gray('·');
    const ms = r.latencyMs != null ? dim(` ${r.latencyMs}ms`) : '';
    console.log(`      ${icon} ${String(r.title).padEnd(34)}${ms}`);
    console.log(`         ${OK_STATES.has(r.state) ? dim(r.statement) : r.statement}`);
  }
}

export async function cmdSelftest(flags = {}) {
  const vendors = resolveVendors(flags);
  const cfg = loadConfig();
  const { url, apiKey } = resolveSettings(cfg);
  const strict = !!flags.strict;
  const startedAt = new Date().toISOString();

  const statics = vendors.map((v) => staticCheck(v));
  const env = environmentChecks({
    url,
    apiKey,
    strict: envFlag('SHOMRA_GUARD_STRICT'),
    breakerOpen: breakerOpen(),
    subjectTypes: readSubjectTypes({ url }),
  });

  let session = null;
  let liveError = null;
  if (url && apiKey) {
    try {
      const started = await startSession(url, apiKey, machineInfo(cfg), vendors);
      if (!started?.nonce || !started?.marker) throw new Error('the server did not issue a self-test nonce (an older backend)');
      session = started;
      /**
       * ⚠ The hook decides what to escalate against the set it has CACHED, so the
       * expectation is computed against the same value - refreshed here from the
       * answer the server just gave, which is what any escalation would have
       * refreshed it with anyway.
       */
      if (Array.isArray(started.subjectTypes)) rememberSubjectTypes(started.subjectTypes, { url });
    } catch (e) {
      liveError = e?.message ?? String(e);
    }
  } else {
    liveError = 'no server or credentials configured on this machine';
  }

  const subjectTypes = session && Array.isArray(session.subjectTypes) ? session.subjectTypes : readSubjectTypes({ url });

  let root = null;
  const results = [];
  try {
    if (session) root = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-selftest-'));
    for (const s of statics) {
      const canaries = session && s.installs.length
        ? await runVendor({ vendor: s.vendor, statics: s, session: { ...session, marker: session.marker }, root, subjectTypes })
        : [];
      results.push(rollUpVendor(s, canaries));
    }
  } finally {
    if (root) fs.rmSync(root, { recursive: true, force: true });
  }

  const report = {
    at: startedAt,
    finishedAt: new Date().toISOString(),
    agentVersion: VERSION,
    machine: { machineId: cfg.machineId ?? null, hostname: os.hostname(), platform: process.platform },
    live: !!session,
    liveError,
    subjectTypes: subjectTypes ?? null,
    environment: env,
    vendors: results.map((v) => ({
      vendor: v.vendor,
      label: v.label,
      state: v.state,
      escalated: v.escalated,
      canaries: v.canaries.map((c) => ({ canary: c.canary, state: c.state, statement: c.statement, decision: c.decision ?? null, latencyMs: c.latencyMs ?? null, expectEscalation: c.expectEscalation })),
      static: {
        state: v.static.state,
        files: v.static.files,
        missing: (v.static.missing ?? []).map((m) => m.name),
        missingEvents: (v.static.missingEvents ?? []).map((m) => m.name),
        statement: v.static.statement,
        fix: v.static.fix,
      },
    })),
  };

  if (session) {
    try {
      await api(url, apiKey, '/gate/selftest/report', { nonce: session.nonce, report }, { timeoutMs: 15_000 });
      report.reported = true;
    } catch (e) {
      report.reported = false;
      report.reportError = e?.message ?? String(e);
    }
  }

  const code = exitCodeFor(results, { strict });
  if (flags.json) {
    process.stdout.write(`${JSON.stringify({ ...report, exitCode: code }, null, 2)}\n`);
    return code === 0 ? undefined : process.exit(code);
  }

  console.log(bold(cyan('\n  Shomra self-test')) + dim(` · ${os.hostname()} · ${results.length} agent${results.length === 1 ? '' : 's'}`));
  console.log(dim('  Whether this machine\'s agents actually put their tool calls in front of your policy.\n'));

  for (const r of env) console.log(`  ${r.ok ? green('✓') : yellow('!')} ${String(r.label).padEnd(22)} ${dim(r.detail)}`);
  /** ⚠ Said ONCE, not per agent: a machine that could not reach the server proved nothing anywhere, and repeating it per row buries the readings that ARE evidence. */
  if (!session) console.log(`  ${yellow('!')} ${'Live canaries'.padEnd(22)} ${dim(`not run (${liveError}) - the static reading below is all that was measured`)}`);

  if (!results.length) {
    console.log(yellow('\n  ○ No supported coding agent is installed on this machine, so there is nothing to test.'));
    console.log(dim('    Install one and run `shomra install-hook --agent all`.\n'));
    return code === 0 ? undefined : process.exit(code);
  }

  console.log('');
  for (const v of results) {
    printStatic(v.static);
    if (v.canaries.length) printCanaries(v.canaries);
    console.log('');
  }

  const porous = results.filter((v) => v.state === 'porous' || v.state === 'stale');
  const failed = results.filter((v) => v.state === 'failed');
  if (porous.length) {
    console.log(`  ${red('✗')} ${porous.length} agent${porous.length === 1 ? ' has' : 's have'} calls that reach no screen: ${porous.map((v) => v.label).join(', ')}.`);
    console.log(`    ${dim('Fix:')} ${bold(porous.map((v) => v.static.fix).join(' && '))}`);
  }
  if (failed.length) console.log(`  ${red('✗')} ${failed.length} agent${failed.length === 1 ? '' : 's'} escalated without getting an answer this test could verify.`);
  if (!porous.length && !failed.length) {
    console.log(`  ${green('✓')} Every installed agent's tool calls pass through the hook, and every canary the org has a rule for reached the server.`);
  }
  if (session) console.log(dim(`  ${report.reported ? 'Reported to' : 'Could not report to'} ${url} - the org's fleet coverage now includes this machine.`));
  console.log('');

  return code === 0 ? undefined : process.exit(code);
}
