import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { bold, dim, green, red, yellow } from '../core/terminal.mjs';
import { recordLabel, telemetryContext } from '../telemetry/record.mjs';

export function describeVerdict(last) {
  const what = last.t ?? last.kind ?? last.c;
  const rule = last.r?.[0]?.k ?? 'no rule';
  return `${last.d} ${what} · ${rule}${last.sh ? ` · ${last.sh}` : ''} · ${last.at}`;
}

export function cmdFeedback(flags, { stdin = process.stdin, stdout = process.stdout, ctx = telemetryContext() } = {}) {
  if (!flags.fp) {
    console.error(`${red('✗')} Usage: ${bold('shomra feedback --fp')} ${dim('- mark the most recent block or flag on this machine as a false positive')}`);
    process.exit(EXIT_USAGE);
  }
  if (!stdin?.isTTY || !stdout?.isTTY) {
    console.error(`${red('✗')} ${bold('shomra feedback')} is for a person at a terminal. ${dim('It is refused without one, so an agent that was just blocked cannot file its own appeal.')}`);
    process.exit(EXIT_USAGE);
  }
  if (!ctx.state.enabled) {
    console.log(`\n  ${yellow('○')} Telemetry is off ${dim(`- ${ctx.state.reason}`)}. ${dim('Feedback travels on that channel; turn it on with')} ${bold('shomra telemetry on')}${dim('.')}\n`);
    return;
  }
  const last = ctx.store?.lastVerdict();
  if (!last?.id) {
    console.log(`\n  ${dim('No recent block or flag on this machine to mark.')}\n`);
    return;
  }
  const id = recordLabel({ channel: last.c, label: 'feedback-fp', ref: last.id, rules: last.r, kind: last.kind, tool: last.t, shape: last.sh }, ctx);
  if (!id) {
    console.log(`\n  ${red('✗')} Could not queue the feedback ${dim('- the telemetry directory is not writable.')}\n`);
    process.exitCode = 1;
    return;
  }
  console.log(`\n  ${green('✓')} Marked as a false positive: ${dim(describeVerdict(last))}`);
  console.log(`  ${dim('Queued with the next telemetry flush. To stop this rule firing here now, add it to')} ${bold('.shomraignore')}${dim('.')}\n`);
}
