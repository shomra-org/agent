import path from 'node:path';
import { CONFIG_DIR, loadConfig, resolveSettings } from '../core/config.mjs';
import { telemetryState } from './consent.mjs';
import { gateRule, labelEvent, tickOf, verdictEvent } from './events.mjs';
import { maybeFlushInBackground } from './flush.mjs';
import { makeTelemetryStore } from './store.mjs';

export const TELEMETRY_DIR = path.join(CONFIG_DIR, 'telemetry');

const REMEMBERED = new Set(['tool', 'result', 'mcp', 'add']);

const OFF = { enabled: false, level: 'off', reason: 'the config could not be read' };

export function telemetryContext(cfg, { dir = TELEMETRY_DIR, env = process.env } = {}) {
  try {
    const c = cfg ?? loadConfig();
    const enrolled = !!resolveSettings(c).apiKey;
    return { state: telemetryState({ env, cfg: c, enrolled }), salt: c?.telemetry?.salt ?? null, store: makeTelemetryStore(dir), env };
  } catch {
    return { state: OFF, salt: null, store: null, env };
  }
}

export function recordVerdict(input, ctx = telemetryContext()) {
  try {
    if (!ctx?.state?.enabled || !ctx.store) return null;
    const ev = verdictEvent({ ...input, level: ctx.state.level, salt: ctx.salt });
    if (ev.d === 'ALLOW' && !ev.r?.some((r) => r.k.startsWith('shadow:'))) {
      ctx.store.append(tickOf(ev));
    } else {
      ctx.store.append(ev);
      if (REMEMBERED.has(ev.c)) ctx.store.remember(ev);
    }
    maybeFlushInBackground({ store: ctx.store, env: ctx.env });
    return ev.id;
  } catch {
    return null;
  }
}

export function recordAcquisition(kind, verdict, findings, forced, ctx = telemetryContext()) {
  const ref = recordVerdict({ channel: 'add', kind, verdict, findings, rule: gateRule, decidedBy: 'local' }, ctx);
  if (verdict === 'BLOCK' && forced) recordLabel({ channel: 'add', label: 'forced', ref, kind, findings, rule: gateRule }, ctx);
  return ref;
}

export function recordLabel(input, ctx = telemetryContext()) {
  try {
    if (!ctx?.state?.enabled || !ctx.store) return null;
    const ev = labelEvent(input);
    ctx.store.append(ev);
    maybeFlushInBackground({ store: ctx.store, env: ctx.env });
    return ev.id;
  } catch {
    return null;
  }
}
