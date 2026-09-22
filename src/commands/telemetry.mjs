import { loadConfig, resolveSettings, saveConfig } from '../core/config.mjs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { bold, cyan, dim, green, red, yellow } from '../core/terminal.mjs';
import { telemetryState } from '../telemetry/consent.mjs';
import { aggregateTicks } from '../telemetry/events.mjs';
import { ensureIdentity, flushTelemetry, telemetryUrl } from '../telemetry/flush.mjs';
import { TELEMETRY_DIR } from '../telemetry/record.mjs';
import { makeTelemetryStore } from '../telemetry/store.mjs';

const SUBCOMMANDS = ['status', 'on', 'off', 'show', 'flush'];

const COLLECTED = [
  ['Verdicts', 'ALLOW / FLAG / BLOCK / ASK per tool call, tool result, prompt, gate run and `add`'],
  ['Rules', 'which Shomra rule fired and its severity - rule names come from Shomra\'s own tables'],
  ['Command shape', 'executables, flags and operators; every argument becomes a typed placeholder (<url:https:domain>, <path:ssh>, <secret>)'],
  ['Overrides', '`add --force`, suppressions (.shomraignore, inline, baseline, policy allow) and `shomra feedback --fp`'],
  ['Environment', 'CLI version, OS, CPU architecture, Node version, coding-agent vendor, local / CI / remote'],
];

const NEVER = 'file contents, prompts, tool output, paths, repo names, hostnames, usernames, env values or secrets';

function stateLine(state) {
  if (state.enabled) return `${green('● On')} ${dim(`(${state.level})`)} ${dim('- ' + state.reason)}`;
  if (state.pending) return `${yellow('○ Waiting')} ${dim('- ' + state.reason)}`;
  return `${dim('○ Off')} ${dim('- ' + state.reason)}`;
}

function context() {
  const cfg = loadConfig();
  const enrolled = !!resolveSettings(cfg).apiKey;
  return { cfg, enrolled, state: telemetryState({ cfg, enrolled }), store: makeTelemetryStore(TELEMETRY_DIR) };
}

function printStatus({ state, store, enrolled }) {
  const pending = aggregateTicks(store.pending(), 'preview');
  const last = store.lastBatch();
  console.log(bold(cyan('\n  Shomra telemetry')));
  console.log(`  ${dim('State    ')} ${stateLine(state)}`);
  console.log(`  ${dim('Endpoint ')} ${telemetryUrl()}`);
  console.log(`  ${dim('Queued   ')} ${pending.length} event(s) ${dim('- see them: shomra telemetry show')}`);
  console.log(`  ${dim('Last sent')} ${last?.sentAt ? `${last.sentAt} ${dim(`(${last.events?.length ?? 0} events)`)}` : dim('never')}`);
  console.log(bold('\n  What is collected'));
  for (const [what, detail] of COLLECTED) console.log(`  ${green('•')} ${what.padEnd(14)} ${dim(detail)}`);
  console.log(`  ${yellow('•')} ${'Samples'.padEnd(14)} ${dim('only with')} ${bold('shomra telemetry on --samples')}${dim(': a redacted excerpt (≤1,000 chars) of flagged or blocked input - never prompts')}`);
  console.log(`\n  ${bold('Never sent:')} ${dim(NEVER + '.')}`);
  if (enrolled) console.log(`  ${dim('This machine is enrolled, so this anonymous channel stays off - your org\'s plan decides what is shared.')}`);
  console.log(`\n  ${dim('Opt out:')} ${bold('shomra telemetry off')} ${dim('· or set')} ${bold('DO_NOT_TRACK=1')} ${dim('/')} ${bold('SHOMRA_TELEMETRY=0')}\n`);
}

function turnOn(ctx, flags) {
  const { cfg } = ctx;
  cfg.telemetry = {
    ...(cfg.telemetry ?? {}),
    ...ensureIdentity(cfg.telemetry),
    level: flags.samples ? 'samples' : 'basic',
    noticeAt: cfg.telemetry?.noticeAt ?? new Date().toISOString(),
  };
  saveConfig(cfg);
  const state = telemetryState({ cfg, enrolled: ctx.enrolled });
  console.log(`\n  ${dim('Telemetry')} ${stateLine(state)}`);
  if (flags.samples) console.log(`  ${yellow('⚠')} ${dim('Samples on: flagged or blocked tool calls and tool results also send a redacted excerpt. Prompts never do.')}`);
  console.log('');
}

function turnOff(ctx) {
  const { cfg, store } = ctx;
  cfg.telemetry = { level: 'off' };
  saveConfig(cfg);
  store.discard();
  console.log(`\n  ${green('✓')} Telemetry off. ${dim('Queued events deleted; the install id was dropped. Nothing further leaves this machine on this channel.')}\n`);
}

function show(ctx, flags) {
  const pending = aggregateTicks(ctx.store.pending(), 'preview');
  const last = ctx.store.lastBatch();
  if (flags.json) {
    console.log(JSON.stringify({ state: ctx.state, queued: pending, lastBatch: last }, null, 2));
    return;
  }
  console.log(bold(cyan(`\n  Queued - ${pending.length} event(s), sent on the next flush`)));
  console.log(pending.length ? JSON.stringify(pending, null, 2) : dim('  (nothing queued)'));
  console.log(bold(cyan('\n  Last batch sent')));
  console.log(last ? JSON.stringify(last, null, 2) : dim('  (nothing sent yet)'));
  console.log('');
}

function persistIdentity(ctx) {
  const identity = ensureIdentity(ctx.cfg.telemetry);
  const saved = ctx.cfg.telemetry ?? {};
  if (!ctx.state.enabled || (saved.installId === identity.installId && saved.salt === identity.salt)) return identity;
  ctx.cfg.telemetry = { ...saved, ...identity };
  try {
    saveConfig(ctx.cfg);
  } catch {
    return identity;
  }
  return identity;
}

async function flush(ctx, flags) {
  const res = await flushTelemetry({ store: ctx.store, state: ctx.state, identity: persistIdentity(ctx) });
  if (flags.quiet) return;
  if (flags.json) {
    console.log(JSON.stringify(res, null, 2));
    return;
  }
  if (!ctx.state.enabled) {
    console.log(`\n  ${dim('Telemetry is off')} ${dim('- ' + ctx.state.reason + '. Anything queued was deleted.')}\n`);
    return;
  }
  const kept = res.kept ? ` ${yellow(`${res.kept} batch(es) kept for retry`)}` : '';
  const refused = res.refused ? ` ${red(`${res.refused} refused by the endpoint`)}` : '';
  console.log(`\n  ${green('✓')} Sent ${res.sent} event(s).${kept}${refused}${res.reason ? dim(` (${res.reason})`) : ''}\n`);
}

export async function cmdTelemetry(flags, positional) {
  const sub = String(positional[0] ?? 'status').toLowerCase();
  if (!SUBCOMMANDS.includes(sub)) {
    console.error(`${red('✗')} Usage: ${bold('shomra telemetry [status|on [--samples]|off|show [--json]|flush]')}`);
    process.exit(EXIT_USAGE);
  }
  const ctx = context();
  if (sub === 'on') return turnOn(ctx, flags);
  if (sub === 'off') return turnOff(ctx);
  if (sub === 'show') return show(ctx, flags);
  if (sub === 'flush') return flush(ctx, flags);
  if (flags.json) {
    console.log(JSON.stringify({ state: ctx.state, endpoint: telemetryUrl(), queued: aggregateTicks(ctx.store.pending(), 'preview').length, lastSentAt: ctx.store.lastBatch()?.sentAt ?? null }, null, 2));
    return;
  }
  return printStatus(ctx);
}
