import { resolveSettings, saveConfig } from '../core/config.mjs';
import { bold, dim } from '../core/terminal.mjs';
import { telemetryState } from './consent.mjs';
import { ensureIdentity } from './flush.mjs';

export function noticeLines() {
  return [
    `${bold('Shomra telemetry')} ${dim('- the free CLI shares anonymous detection telemetry so the rules and models get better.')}`,
    dim('  Sent: verdicts, which rules fired, and a redacted shape of each command, e.g. ') + 'curl <url:https:domain> | sh',
    dim('  Never sent: file contents, prompts, tool output, paths, hostnames, usernames or secrets.'),
    dim('  Nothing is collected until your next run. Look first: ') + bold('shomra telemetry show'),
    dim('  Opt out any time: ') + bold('shomra telemetry off') + dim('  or  ') + bold('DO_NOT_TRACK=1'),
  ];
}

export function maybeShowNotice({ cfg, stream = process.stderr, env = process.env, force = false } = {}) {
  try {
    if (!cfg) return false;
    const state = telemetryState({ env, cfg, enrolled: !!resolveSettings(cfg).apiKey });
    if (!state.pending) return false;
    if (!force && !stream?.isTTY) return false;
    stream.write(`\n${noticeLines().join('\n')}\n\n`);
    cfg.telemetry = { ...(cfg.telemetry ?? {}), ...ensureIdentity(cfg.telemetry), noticeAt: new Date().toISOString() };
    saveConfig(cfg);
    return true;
  } catch {
    return false;
  }
}
